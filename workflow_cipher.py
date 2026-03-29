import copy
import json
import os
import random
import uuid
from collections import defaultdict
from datetime import datetime, timezone

import folder_paths
from comfy_execution.graph_utils import ExecutionBlocker, GraphBuilder, is_link

from .crypto_utils import decrypt_payload, encrypt_payload, sanitize_filename
from .key_store import get_workflow_group_status, validate_access_key


MAX_SHELL_PORTS = 16
PUBLIC_INPUT_NAMES = tuple(f"input_{index}" for index in range(1, MAX_SHELL_PORTS + 1))
BRIDGE_INPUT_NAMES = tuple(f"value_{index}" for index in range(1, MAX_SHELL_PORTS + 1))
SHELL_OUTPUT_NAMES = tuple(f"out_{index}" for index in range(1, MAX_SHELL_PORTS + 1))
BRAND_NAME = "XLJworkflowCipher"
VAULT_DISPLAY_NAME = "ComfyUI-XLJworkflowCipher"
CATEGORY_NAME = "advanced/XLJworkflowCipher"


class AnyType(str):
    def __eq__(self, _other):
        return True

    def __ne__(self, _other):
        return False


ANY = AnyType("*")
ANY_PORT_TYPES = tuple(ANY for _ in range(MAX_SHELL_PORTS))


def _normalize_link(link):
    if not is_link(link):
        return None
    return [str(link[0]), int(link[1])]


def _link_key(link):
    normalized = _normalize_link(link)
    if normalized is None:
        raise ValueError(f"Invalid link reference: {link!r}")
    return f"{normalized[0]}::{normalized[1]}"


def _find_workflow_node(workflow, node_id):
    for node in workflow.get("nodes", []):
        if str(node.get("id")) == str(node_id):
            return node
    raise ValueError(f"Unable to locate workflow node {node_id}.")


def _refresh_node_link_references(workflow):
    incoming = {}
    outgoing = defaultdict(list)
    for raw_link in workflow.get("links", []):
        if len(raw_link) < 5:
            continue
        outgoing[(int(raw_link[1]), int(raw_link[2]))].append(int(raw_link[0]))
        incoming[(int(raw_link[3]), int(raw_link[4]))] = int(raw_link[0])

    for node in workflow.get("nodes", []):
        node_id = int(node["id"])
        for index, input_slot in enumerate(node.get("inputs", [])):
            input_slot["link"] = incoming.get((node_id, index))
        for index, output_slot in enumerate(node.get("outputs", [])):
            slot_index = int(output_slot.get("slot_index", index))
            output_slot["links"] = outgoing.get((node_id, slot_index), [])


def _build_shell_node_input_map(link_records):
    mapping = {}
    ordered = []
    for link in link_records:
        key = _link_key([str(link["source"]), link["source_slot"]])
        if key in mapping:
            continue
        mapping[key] = len(ordered)
        ordered.append(
            {
                "source": int(link["source"]),
                "source_slot": int(link["source_slot"]),
                "type": link.get("type") or "*",
                "key": key,
            }
        )
    return ordered, mapping


def _build_shell_node_output_map(link_records):
    mapping = {}
    ordered = []
    for link in link_records:
        key = _link_key([str(link["source"]), link["source_slot"]])
        if key not in mapping:
            mapping[key] = len(ordered)
            ordered.append(
                {
                    "source": int(link["source"]),
                    "source_slot": int(link["source_slot"]),
                    "type": link.get("type") or "*",
                    "key": key,
                }
            )
    return ordered, mapping


class WorkflowCipherSelectionBuilder:
    def __init__(
        self,
        workflow,
        prompt,
        template_id,
        selected_node_ids,
        node_title=None,
        key_required=False,
        key_group="",
    ):
        if not isinstance(workflow, dict) or not isinstance(prompt, dict):
            raise ValueError("WorkflowCipher selection encryption requires workflow and prompt data.")

        self.workflow = copy.deepcopy(workflow)
        self.prompt = {str(key): value for key, value in copy.deepcopy(prompt).items()}
        self.template_id = template_id
        self.node_title = (node_title or "").strip()
        self.key_required = bool(key_required)
        self.key_group = (key_group or "").strip()
        if self.key_required and not self.key_group:
            raise ValueError("Key mode requires a workflow group code or name.")
        self.selected_node_ids = {int(node_id) for node_id in selected_node_ids}
        if not self.selected_node_ids:
            raise ValueError("Select at least one node to encrypt.")

        self.workflow_nodes = {}
        self.links_by_source = defaultdict(list)
        self.links_by_target = defaultdict(list)
        self.external_inputs = []
        self.external_outputs = []
        self.secret_prompt = {}
        self._load_workflow_maps()

    def _load_workflow_maps(self):
        for node in self.workflow.get("nodes", []):
            node_id = int(node["id"])
            self.workflow_nodes[node_id] = node

        missing = sorted(node_id for node_id in self.selected_node_ids if node_id not in self.workflow_nodes)
        if missing:
            raise ValueError(f"Selected nodes are missing from the workflow: {missing}")

        for node_id in self.selected_node_ids:
            node_type = self.workflow_nodes[node_id].get("type")
            if node_type in {
                "WorkflowCipherEncryptNode",
                "WorkflowCipherBridgeNode",
                "WorkflowCipherDecryptNode",
                "WorkflowCipherVaultNode",
            }:
                raise ValueError("WorkflowCipher control nodes cannot be encrypted again.")

        for raw_link in self.workflow.get("links", []):
            if len(raw_link) < 5:
                continue
            link_record = {
                "id": int(raw_link[0]),
                "source": int(raw_link[1]),
                "source_slot": int(raw_link[2]),
                "target": int(raw_link[3]),
                "target_slot": int(raw_link[4]),
                "type": raw_link[5] if len(raw_link) > 5 else None,
                "raw": list(raw_link),
            }
            self.links_by_source[link_record["source"]].append(link_record)
            self.links_by_target[link_record["target"]].append(link_record)

    def analyze(self):
        for raw_link in self.workflow.get("links", []):
            if len(raw_link) < 5:
                continue
            source_id = int(raw_link[1])
            target_id = int(raw_link[3])
            if source_id not in self.selected_node_ids and target_id in self.selected_node_ids:
                self.external_inputs.append(
                    {
                        "id": int(raw_link[0]),
                        "source": source_id,
                        "source_slot": int(raw_link[2]),
                        "target": target_id,
                        "target_slot": int(raw_link[4]),
                        "type": raw_link[5] if len(raw_link) > 5 else None,
                    }
                )
            elif source_id in self.selected_node_ids and target_id not in self.selected_node_ids:
                self.external_outputs.append(
                    {
                        "id": int(raw_link[0]),
                        "source": source_id,
                        "source_slot": int(raw_link[2]),
                        "target": target_id,
                        "target_slot": int(raw_link[4]),
                        "type": raw_link[5] if len(raw_link) > 5 else None,
                    }
                )

        if not self.external_outputs:
            raise ValueError(
                "Selected nodes must connect to at least one downstream node outside the encrypted group."
            )

        ordered_inputs, _ = _build_shell_node_input_map(self.external_inputs)
        ordered_outputs, _ = _build_shell_node_output_map(self.external_outputs)
        if len(ordered_inputs) > MAX_SHELL_PORTS:
            raise ValueError(
                f"WorkflowCipher supports at most {MAX_SHELL_PORTS} public inputs per encrypted shell."
            )
        if len(ordered_outputs) > MAX_SHELL_PORTS:
            raise ValueError(
                f"WorkflowCipher supports at most {MAX_SHELL_PORTS} public outputs per encrypted shell."
            )

        for node_id in sorted(self.selected_node_ids):
            prompt_node = self.prompt.get(str(node_id))
            if prompt_node is not None:
                self.secret_prompt[str(node_id)] = prompt_node

        if not self.secret_prompt:
            raise ValueError(
                "WorkflowCipher could not find executable prompt data for the selected nodes."
            )

    def build_secret_payload(self):
        ordered_outputs, _ = _build_shell_node_output_map(self.external_outputs)
        ordered_inputs, _ = _build_shell_node_input_map(self.external_inputs)
        restore_nodes = [
            copy.deepcopy(self.workflow_nodes[node_id])
            for node_id in sorted(self.selected_node_ids)
        ]
        restore_links = [
            copy.deepcopy(raw_link)
            for raw_link in self.workflow.get("links", [])
            if int(raw_link[1]) in self.selected_node_ids
            or int(raw_link[3]) in self.selected_node_ids
        ]
        return {
            "version": 1,
            "template_id": self.template_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "secret_prompt": self.secret_prompt,
            "outputs": [
                [str(record["source"]), int(record["source_slot"])] for record in ordered_outputs
            ],
            "public_inputs": list(PUBLIC_INPUT_NAMES[: len(ordered_inputs)]),
            "secret_node_count": len(self.secret_prompt),
            "restore_nodes": restore_nodes,
            "restore_links": restore_links,
        }

    def build_shell_workflow(self, packed_payload, passphrase=""):
        selected_ids = self.selected_node_ids
        shell = copy.deepcopy(self.workflow)

        ordered_inputs, input_index_by_key = _build_shell_node_input_map(self.external_inputs)
        ordered_outputs, output_index_by_key = _build_shell_node_output_map(self.external_outputs)

        shell_node_id = max(self.workflow_nodes) + 1
        next_link_id = max((int(link[0]) for link in shell.get("links", [])), default=0) + 1

        selected_nodes = [self.workflow_nodes[node_id] for node_id in sorted(selected_ids)]
        min_x = min(float(node.get("pos", [0, 0])[0]) for node in selected_nodes)
        min_y = min(float(node.get("pos", [0, 0])[1]) for node in selected_nodes)
        node_height = max(160, 110 + (max(len(ordered_inputs), len(ordered_outputs)) * 26))
        default_title = self.node_title or VAULT_DISPLAY_NAME

        shell["nodes"] = [
            node for node in shell.get("nodes", []) if int(node["id"]) not in selected_ids
        ]
        shell["links"] = [
            raw_link
            for raw_link in shell.get("links", [])
            if int(raw_link[1]) not in selected_ids and int(raw_link[3]) not in selected_ids
        ]

        input_labels = []
        for record in ordered_inputs:
            label = record.get("type") or "*"
            source_node = self.workflow_nodes.get(record["source"])
            if source_node:
                outputs = source_node.get("outputs", [])
                slot = record["source_slot"]
                if 0 <= slot < len(outputs):
                    slot_name = outputs[slot].get("name") or outputs[slot].get("type") or label
                    label = slot_name
            input_labels.append(label)

        output_labels = []
        for record in ordered_outputs:
            label = record.get("type") or "*"
            source_node = self.workflow_nodes.get(record["source"])
            if source_node:
                outputs = source_node.get("outputs", [])
                slot = record["source_slot"]
                if 0 <= slot < len(outputs):
                    slot_name = outputs[slot].get("name") or outputs[slot].get("type") or label
                    label = slot_name
            output_labels.append(label)

        shell_node = {
            "id": shell_node_id,
            "type": "WorkflowCipherVaultNode",
            "pos": [min_x, min_y],
            "size": [300, node_height],
            "flags": {},
            "order": max((int(node.get("order", 0)) for node in self.workflow.get("nodes", [])), default=0) + 1,
            "mode": 0,
            "title": default_title,
            "inputs": [
                {"name": PUBLIC_INPUT_NAMES[index], "type": record["type"], "link": None}
                for index, record in enumerate(ordered_inputs)
            ],
            "outputs": [
                {"name": SHELL_OUTPUT_NAMES[index], "type": record["type"], "links": []}
                for index, record in enumerate(ordered_outputs)
            ],
            "properties": {
                "Node name for S&R": "WorkflowCipherVaultNode",
                "workflowcipher_pack": packed_payload,
                "workflowcipher_runtime_key": passphrase.strip(),
                "workflowcipher_template_id": self.template_id,
                "workflowcipher_secret_nodes": len(self.secret_prompt),
                "workflowcipher_input_count": len(ordered_inputs),
                "workflowcipher_output_count": len(ordered_outputs),
                "workflowcipher_input_labels": input_labels,
                "workflowcipher_output_labels": output_labels,
                "workflowcipher_key_required": self.key_required,
                "workflowcipher_key_group": self.key_group,
            },
            "widgets_values": ["", ""],
        }
        shell["nodes"].append(shell_node)

        for index, record in enumerate(ordered_inputs):
            shell["links"].append(
                [
                    next_link_id,
                    record["source"],
                    record["source_slot"],
                    shell_node_id,
                    index,
                    record["type"],
                ]
            )
            next_link_id += 1

        for link in self.external_outputs:
            output_index = output_index_by_key[
                _link_key([str(link["source"]), link["source_slot"]])
            ]
            shell["links"].append(
                [
                    next_link_id,
                    shell_node_id,
                    output_index,
                    int(link["target"]),
                    int(link["target_slot"]),
                    link.get("type") or "*",
                ]
            )
            next_link_id += 1

        shell["last_node_id"] = max(int(shell.get("last_node_id", 0)), shell_node_id)
        shell["last_link_id"] = max(int(shell.get("last_link_id", 0)), next_link_id - 1)
        _refresh_node_link_references(shell)
        return shell, shell_node_id

    def pack_shell_workflow(self, passphrase):
        self.analyze()
        payload = self.build_secret_payload()
        packed_payload = encrypt_payload(payload, passphrase.strip())
        return self.build_shell_workflow(packed_payload, passphrase)


def encrypt_selection_to_shell_workflow(
    workflow,
    prompt,
    selected_node_ids,
    passphrase,
    template_id=None,
    node_title=None,
    key_required=False,
    key_group=None,
):
    template_id = (template_id or "").strip() or uuid.uuid4().hex
    if len(template_id) < 8:
        raise ValueError("Template ID must be at least 8 characters.")
    if not (passphrase or "").strip():
        raise ValueError("Passphrase cannot be empty.")

    builder = WorkflowCipherSelectionBuilder(
        workflow=workflow,
        prompt=prompt,
        template_id=template_id,
        selected_node_ids=selected_node_ids,
        node_title=node_title,
        key_required=key_required,
        key_group=key_group,
    )
    shell_workflow, shell_node_id = builder.pack_shell_workflow(passphrase)
    return {
        "workflow": shell_workflow,
        "shell_node_id": shell_node_id,
        "template_id": template_id,
    }


def decrypt_selection_to_shell_workflow(workflow, shell_node_id, passphrase):
    if not isinstance(workflow, dict):
        raise ValueError("WorkflowCipher decryption requires workflow data.")

    shell = copy.deepcopy(workflow)
    shell_node = _find_workflow_node(shell, shell_node_id)
    properties = shell_node.get("properties", {})
    packed_payload = properties.get("workflowcipher_pack", "")
    if not packed_payload:
        raise ValueError("Encrypted WorkflowCipher payload is missing.")

    # Remember key info before deleting shell node
    remembered_key_required = bool(properties.get("workflowcipher_key_required"))
    remembered_key_group = (properties.get("workflowcipher_key_group") or "").strip()

    effective_passphrase = (passphrase or "").strip()
    if not effective_passphrase:
        key_group = (properties.get("workflowcipher_key_group") or "").strip()
        group_status = get_workflow_group_status(key_group) if key_group else None
        if group_status and group_status.get("status") == "destroyed":
            effective_passphrase = (properties.get("workflowcipher_runtime_key") or "").strip()
    payload = decrypt_payload(packed_payload, effective_passphrase)
    restore_nodes = copy.deepcopy(payload.get("restore_nodes") or [])
    restore_links = copy.deepcopy(payload.get("restore_links") or [])
    if not restore_nodes:
        raise ValueError("This WorkflowCipher node does not contain restorable workflow data.")

    shell_node_id = int(shell_node_id)
    shell["nodes"] = [
        node for node in shell.get("nodes", []) if int(node["id"]) != shell_node_id
    ]
    shell["links"] = [
        raw_link
        for raw_link in shell.get("links", [])
        if int(raw_link[1]) != shell_node_id and int(raw_link[3]) != shell_node_id
    ]

    existing_ids = {int(node["id"]) for node in shell.get("nodes", [])}
    next_node_id = max(existing_ids, default=0) + 1
    restore_node_ids = {int(node["id"]) for node in restore_nodes}
    remap = {}
    for node in restore_nodes:
        original_id = int(node["id"])
        if original_id in existing_ids:
            remap[original_id] = next_node_id
            next_node_id += 1
        else:
            remap[original_id] = original_id
        existing_ids.add(remap[original_id])
        node["id"] = remap[original_id]

    link_id_start = max((int(link[0]) for link in shell.get("links", [])), default=0) + 1
    remapped_links = []
    final_node_ids = existing_ids.copy()
    for raw_link in restore_links:
        updated = list(raw_link)
        source_id = int(updated[1])
        target_id = int(updated[3])
        if source_id in remap:
            updated[1] = remap[source_id]
            source_id = int(updated[1])
        if target_id in remap:
            updated[3] = remap[target_id]
            target_id = int(updated[3])
        if source_id not in final_node_ids or target_id not in final_node_ids:
            continue
        updated[0] = link_id_start
        link_id_start += 1
        remapped_links.append(updated)

    shell["nodes"].extend(restore_nodes)
    shell["links"].extend(remapped_links)
    shell["last_node_id"] = max((int(node["id"]) for node in shell["nodes"]), default=0)
    shell["last_link_id"] = max((int(link[0]) for link in shell["links"]), default=0)
    _refresh_node_link_references(shell)

    return {
        "workflow": shell,
        "restored_node_ids": [int(node["id"]) for node in restore_nodes],
        "remembered_key_required": remembered_key_required,
        "remembered_key_group": remembered_key_group,
    }


class WorkflowCipherPlanner:
    def __init__(self, workflow, prompt, template_id):
        if not isinstance(workflow, dict) or not isinstance(prompt, dict):
            raise ValueError("WorkflowCipher requires embedded workflow and prompt data.")

        self.workflow = copy.deepcopy(workflow)
        self.prompt = {str(key): value for key, value in copy.deepcopy(prompt).items()}
        self.template_id = template_id

        self.workflow_nodes = {}
        self.links_by_source = defaultdict(list)
        self.links_by_target = defaultdict(list)
        self.encrypt_node_id = None
        self.bridge_node_id = None
        self.public_upstream_nodes = set()
        self.public_downstream_nodes = set()
        self.secret_nodes = set()
        self._load_workflow_maps()

    def _load_workflow_maps(self):
        for node in self.workflow.get("nodes", []):
            node_id = int(node["id"])
            self.workflow_nodes[node_id] = node
            node_type = node.get("type")
            if node_type == "WorkflowCipherEncryptNode":
                if self.encrypt_node_id is not None:
                    raise ValueError(
                        "WorkflowCipher supports exactly one WorkflowCipherEncryptNode per workflow."
                    )
                self.encrypt_node_id = node_id
            elif node_type == "WorkflowCipherBridgeNode":
                if self.bridge_node_id is not None:
                    raise ValueError(
                        "WorkflowCipher supports exactly one WorkflowCipherBridgeNode per workflow."
                    )
                self.bridge_node_id = node_id

        if self.encrypt_node_id is None:
            raise ValueError("No WorkflowCipherEncryptNode found in workflow.")
        if self.bridge_node_id is None:
            raise ValueError("No WorkflowCipherBridgeNode found in workflow.")

        for raw_link in self.workflow.get("links", []):
            if len(raw_link) < 5:
                continue
            link_record = {
                "id": int(raw_link[0]),
                "source": int(raw_link[1]),
                "source_slot": int(raw_link[2]),
                "target": int(raw_link[3]),
                "target_slot": int(raw_link[4]),
                "type": raw_link[5] if len(raw_link) > 5 else None,
                "raw": list(raw_link),
            }
            self.links_by_source[link_record["source"]].append(link_record)
            self.links_by_target[link_record["target"]].append(link_record)

    def _walk_ancestors(self, start_nodes):
        visited = set()
        stack = list(start_nodes)
        while stack:
            node_id = int(stack.pop())
            if node_id in visited:
                continue
            visited.add(node_id)
            for link in self.links_by_target.get(node_id, []):
                stack.append(link["source"])
        return visited

    def _walk_descendants(self, start_nodes):
        visited = set()
        stack = list(start_nodes)
        while stack:
            node_id = int(stack.pop())
            if node_id in visited:
                continue
            visited.add(node_id)
            for link in self.links_by_source.get(node_id, []):
                stack.append(link["target"])
        return visited

    def _collect_link_sources(self, node_id, allowed_names):
        node = self.workflow_nodes[node_id]
        result = []
        for input_slot in node.get("inputs", []):
            if input_slot.get("name") not in allowed_names:
                continue
            link_id = input_slot.get("link")
            if link_id is None:
                continue
            for link in self.links_by_target.get(node_id, []):
                if link["id"] == int(link_id):
                    result.append(link["source"])
                    break
        return result

    def _collect_link_targets(self, node_id):
        return [link["target"] for link in self.links_by_source.get(node_id, [])]

    def analyze(self):
        public_roots = self._collect_link_sources(self.encrypt_node_id, PUBLIC_INPUT_NAMES)
        if not public_roots:
            raise ValueError(
                "WorkflowCipherEncryptNode needs at least one connected public input."
            )
        self.public_upstream_nodes = self._walk_ancestors(public_roots)

        bridge_roots = self._collect_link_sources(self.bridge_node_id, BRIDGE_INPUT_NAMES)
        if not bridge_roots:
            raise ValueError(
                "WorkflowCipherBridgeNode needs at least one connected encrypted input."
            )
        secret_closure = self._walk_ancestors(bridge_roots)
        self.secret_nodes = secret_closure - self.public_upstream_nodes
        self.secret_nodes.discard(self.encrypt_node_id)
        self.secret_nodes.discard(self.bridge_node_id)
        if not self.secret_nodes:
            raise ValueError(
                "WorkflowCipher did not find any private nodes between Encrypt and Bridge."
            )

        downstream_roots = self._collect_link_targets(self.bridge_node_id)
        if not downstream_roots:
            raise ValueError(
                "WorkflowCipherBridgeNode must be connected to at least one downstream node."
            )
        self.public_downstream_nodes = self._walk_descendants(downstream_roots)

    def build_secret_payload(self):
        bridge_prompt = self.prompt.get(str(self.bridge_node_id))
        if bridge_prompt is None:
            raise ValueError(
                "WorkflowCipherBridgeNode is missing from the execution prompt."
            )

        outputs = [None] * len(BRIDGE_INPUT_NAMES)
        for index, input_name in enumerate(BRIDGE_INPUT_NAMES):
            link_value = bridge_prompt.get("inputs", {}).get(input_name)
            if is_link(link_value):
                outputs[index] = _normalize_link(link_value)

        secret_prompt = {}
        for node_id in sorted(self.secret_nodes):
            prompt_node = self.prompt.get(str(node_id))
            if prompt_node is not None:
                secret_prompt[str(node_id)] = prompt_node

        if not secret_prompt:
            raise ValueError(
                "WorkflowCipher found secret nodes in the workflow graph but none in the prompt."
            )

        return {
            "version": 1,
            "template_id": self.template_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "secret_prompt": secret_prompt,
            "outputs": outputs,
            "public_inputs": list(PUBLIC_INPUT_NAMES),
            "secret_node_count": len(secret_prompt),
        }

    def _refresh_node_link_references(self, workflow):
        _refresh_node_link_references(workflow)

    def export_shell_workflow(self, packed_payload, export_name):
        shell = copy.deepcopy(self.workflow)
        keep_nodes = set(self.public_upstream_nodes)
        keep_nodes.update(self.public_downstream_nodes)
        keep_nodes.add(self.encrypt_node_id)

        shell["nodes"] = [
            node for node in shell.get("nodes", []) if int(node["id"]) in keep_nodes
        ]

        encrypt_node = _find_workflow_node(shell, self.encrypt_node_id)
        bridge_node = self.workflow_nodes[self.bridge_node_id]

        encrypt_node["type"] = "WorkflowCipherDecryptNode"
        encrypt_node["widgets_values"] = [self.template_id, "", ""]
        encrypt_node["outputs"] = copy.deepcopy(bridge_node.get("outputs", []))

        properties = copy.deepcopy(encrypt_node.get("properties", {}))
        properties["Node name for S&R"] = "WorkflowCipherDecryptNode"
        properties["workflowcipher_pack"] = packed_payload
        properties["workflowcipher_template_id"] = self.template_id
        properties["workflowcipher_secret_nodes"] = len(self.secret_nodes)
        properties["workflowcipher_key_required"] = False
        properties["workflowcipher_key_group"] = ""
        encrypt_node["properties"] = properties

        rewritten_links = []
        for raw_link in shell.get("links", []):
            if len(raw_link) < 5:
                continue
            updated = list(raw_link)
            source_id = int(updated[1])
            target_id = int(updated[3])
            if source_id == self.bridge_node_id:
                updated[1] = self.encrypt_node_id
                source_id = self.encrypt_node_id
            if source_id in keep_nodes and target_id in keep_nodes:
                rewritten_links.append(updated)
        shell["links"] = rewritten_links
        shell.pop("groups", None)
        self._refresh_node_link_references(shell)

        safe_name = sanitize_filename(export_name, "comfyui_xljworkflowcipher")
        file_name = f"{safe_name}_{self.template_id[:8]}.json"
        output_path = os.path.join(folder_paths.output_directory, file_name)
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(shell, handle, ensure_ascii=False, indent=2)
        return output_path


class WorkflowCipherRuntime:
    def __init__(self, prompt, unique_id, payload):
        self.prompt = {str(key): value for key, value in prompt.items()}
        self.unique_id = str(unique_id)
        self.payload = payload
        self.secret_prompt = {
            str(key): value for key, value in payload.get("secret_prompt", {}).items()
        }
        self.external_input_map = self._build_external_input_map()

    def _build_external_input_map(self):
        decode_node = self.prompt.get(self.unique_id)
        if decode_node is None:
            raise ValueError(
                f"WorkflowCipherDecryptNode prompt entry {self.unique_id} was not found."
            )
        result = {}
        for input_name, input_value in decode_node.get("inputs", {}).items():
            if input_name in PUBLIC_INPUT_NAMES and is_link(input_value):
                result[_link_key(input_value)] = input_name
        return result

    def expand(self, runtime_kwargs):
        graph = GraphBuilder()
        built_nodes = {}

        def resolve_value(value):
            if not is_link(value):
                return value
            normalized = _normalize_link(value)
            source_id = normalized[0]
            output_index = normalized[1]
            if source_id in self.secret_prompt:
                if source_id not in built_nodes:
                    built_nodes[source_id] = build_node(source_id, self.secret_prompt[source_id])
                return built_nodes[source_id].out(output_index)

            external_input_name = self.external_input_map.get(_link_key(normalized))
            if external_input_name:
                return runtime_kwargs.get(external_input_name)
            raise ValueError(
                f"WorkflowCipher could not resolve external input {source_id}:{output_index}."
            )

        def build_node(node_id, node_data):
            inputs = {}
            for input_name, input_value in node_data.get("inputs", {}).items():
                inputs[input_name] = resolve_value(input_value)
            return graph.node(node_data["class_type"], node_id, **inputs)

        results = []
        for output_value in self.payload.get("outputs", [None] * len(SHELL_OUTPUT_NAMES)):
            if is_link(output_value):
                results.append(resolve_value(output_value))
            else:
                results.append(None)
        return {"result": tuple(results), "expand": graph.finalize()}


class WorkflowCipherEncryptNode:
    def __init__(self):
        pass

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "template_id": ("STRING", {"default": uuid.uuid4().hex}),
                "passphrase": ("STRING", {"default": "", "multiline": False}),
                "export_name": ("STRING", {"default": "comfyui_xljworkflowcipher"}),
            },
            "optional": {name: (ANY, {}) for name in PUBLIC_INPUT_NAMES},
            "hidden": {
                "prompt": "PROMPT",
                "extra_pnginfo": "EXTRA_PNGINFO",
            },
        }

    RETURN_TYPES = ("STRING", "STRING")
    RETURN_NAMES = ("template_id", "workflow_path")
    FUNCTION = "encrypt"
    CATEGORY = CATEGORY_NAME
    OUTPUT_NODE = True

    @classmethod
    def IS_CHANGED(cls, **_kwargs):
        return float("NaN")

    @classmethod
    def VALIDATE_INPUTS(cls, **_kwargs):
        return True

    def encrypt(self, template_id, passphrase, export_name, **kwargs):
        prompt = kwargs.get("prompt")
        extra_pnginfo = kwargs.get("extra_pnginfo")
        workflow = None if extra_pnginfo is None else extra_pnginfo.get("workflow")

        template_id = (template_id or "").strip() or uuid.uuid4().hex
        if len(template_id) < 8:
            raise ValueError("Template ID must be at least 8 characters.")
        if not (passphrase or "").strip():
            raise ValueError("Passphrase cannot be empty.")

        planner = WorkflowCipherPlanner(workflow, prompt, template_id)
        planner.analyze()
        payload = planner.build_secret_payload()
        packed_payload = encrypt_payload(payload, passphrase.strip())
        output_path = planner.export_shell_workflow(packed_payload, export_name)
        return (template_id, output_path)


class WorkflowCipherBridgeNode:
    def __init__(self):
        pass

    @classmethod
    def INPUT_TYPES(cls):
        return {"optional": {name: (ANY, {}) for name in BRIDGE_INPUT_NAMES}}

    RETURN_TYPES = ANY_PORT_TYPES
    RETURN_NAMES = SHELL_OUTPUT_NAMES
    FUNCTION = "bridge"
    CATEGORY = CATEGORY_NAME

    @classmethod
    def IS_CHANGED(cls, **_kwargs):
        return float("NaN")

    @classmethod
    def VALIDATE_INPUTS(cls, **_kwargs):
        return True

    def bridge(self, **kwargs):
        return tuple(kwargs.get(name) for name in BRIDGE_INPUT_NAMES)


class _WorkflowCipherShellBase:
    RETURN_TYPES = ANY_PORT_TYPES
    RETURN_NAMES = SHELL_OUTPUT_NAMES

    @classmethod
    def IS_CHANGED(cls, **_kwargs):
        return float("NaN")

    @classmethod
    def VALIDATE_INPUTS(cls, **_kwargs):
        return True

    def _load_embedded_pack(self, workflow, unique_id):
        node = _find_workflow_node(workflow, unique_id)
        properties = node.get("properties", {})
        packed_payload = properties.get("workflowcipher_pack", "")
        if not packed_payload:
            raise ValueError(
                "Embedded XLJworkflowCipher payload is missing from this workflow."
            )
        return packed_payload

    def _get_runtime_key(self, workflow, unique_id):
        node = _find_workflow_node(workflow, unique_id)
        return (node.get("properties", {}).get("workflowcipher_runtime_key") or "").strip()

    def _require_access_key(self, workflow, unique_id, access_key):
        node = _find_workflow_node(workflow, unique_id)
        properties = node.get("properties", {})
        key_required = bool(properties.get("workflowcipher_key_required"))
        if not key_required:
            return

        key_group = (properties.get("workflowcipher_key_group") or "").strip()
        if not key_group:
            raise ValueError("This workflow requires a key group, but none is configured.")

        validation = validate_access_key(key_group, (access_key or "").strip())
        if validation.get("bypass"):
            return
        if validation.get("valid"):
            return

        status = validation.get("status")
        if status == "missing_key":
            raise ValueError("This workflow requires a valid access key before it can run.")
        if status == "missing_group":
            raise ValueError("The configured workflow key group does not exist.")
        if status == "disabled":
            raise ValueError("This workflow key group has been disabled.")
        if status == "expired":
            raise ValueError("This access key has expired.")
        if status == "invalid_key":
            raise ValueError("The access key is invalid.")
        raise ValueError("The access key could not be validated.")

    def _decrypt_impl(self, passphrase, template_id="", access_key="", **kwargs):
        unique_id = kwargs.get("unique_id")
        prompt = kwargs.get("prompt")
        extra_pnginfo = kwargs.get("extra_pnginfo")
        workflow = None if extra_pnginfo is None else extra_pnginfo.get("workflow")

        self._require_access_key(workflow, unique_id, access_key)
        packed_payload = self._load_embedded_pack(workflow, unique_id)
        effective_passphrase = (passphrase or "").strip()
        if not effective_passphrase:
            effective_passphrase = self._get_runtime_key(workflow, unique_id)
        payload = decrypt_payload(packed_payload, effective_passphrase)
        embedded_template_id = str(payload.get("template_id", ""))
        if template_id and embedded_template_id and template_id != embedded_template_id:
            raise ValueError(
                f"Template ID mismatch. Embedded workflow expects '{embedded_template_id}'."
            )

        runtime = WorkflowCipherRuntime(prompt, unique_id, payload)
        return runtime.expand(kwargs)


class WorkflowCipherDecryptNode(_WorkflowCipherShellBase):
    def __init__(self):
        pass

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "template_id": ("STRING", {"default": ""}),
                "passphrase": ("STRING", {"default": "", "multiline": False}),
                "access_key": ("STRING", {"default": "", "multiline": False}),
            },
            "optional": {name: (ANY, {}) for name in PUBLIC_INPUT_NAMES},
            "hidden": {
                "unique_id": "UNIQUE_ID",
                "prompt": "PROMPT",
                "extra_pnginfo": "EXTRA_PNGINFO",
            },
        }

    FUNCTION = "decrypt"
    CATEGORY = CATEGORY_NAME

    def decrypt(self, template_id, passphrase, access_key, **kwargs):
        return self._decrypt_impl(
            passphrase=passphrase,
            template_id=template_id,
            access_key=access_key,
            **kwargs,
        )


class WorkflowCipherVaultNode(_WorkflowCipherShellBase):
    def __init__(self):
        pass

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "password": ("STRING", {"default": "", "multiline": False}),
                "access_key": ("STRING", {"default": "", "multiline": False}),
            },
            "optional": {name: (ANY, {}) for name in PUBLIC_INPUT_NAMES},
            "hidden": {
                "unique_id": "UNIQUE_ID",
                "prompt": "PROMPT",
                "extra_pnginfo": "EXTRA_PNGINFO",
            },
        }

    FUNCTION = "decrypt"
    CATEGORY = CATEGORY_NAME

    def decrypt(self, password, access_key, **kwargs):
        return self._decrypt_impl(
            passphrase=password,
            template_id="",
            access_key=access_key,
            **kwargs,
        )


class WorkflowCipherRandomSeedNode:
    def __init__(self):
        pass

    @classmethod
    def INPUT_TYPES(cls):
        return {"required": {}}

    RETURN_TYPES = ("INT",)
    RETURN_NAMES = ("seed",)
    FUNCTION = "generate"
    CATEGORY = CATEGORY_NAME

    @classmethod
    def IS_CHANGED(cls, **_kwargs):
        return float("NaN")

    def generate(self):
        return (random.randint(0, 2147483647),)
