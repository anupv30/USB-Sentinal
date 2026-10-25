"""
USB Sentinel AI - Groq AI Threat Intelligence & Intent Engine
Provides:
- Feature 3A: Automated AI Deep Forensic Analysis (JSON structured payload)
- Feature 3B: Natural Language AI Intent Assistant with Tool / Function Calling
"""

import os
import json
import groq
from typing import Callable, Any


DEFAULT_API_KEY = "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"
DEFAULT_MODEL = "qwen/qwen3.8-27b"
FALLBACK_MODELS = ["openai/gpt-oss-120b", "openai/gpt-oss-20b", "allam-2-7b"]

# Tool calling definitions for Groq
FORENSIC_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "quarantine_file",
            "description": "Quarantines and encrypts a specific file from the physical USB drive into the secure vault.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "The exact absolute path of the file to quarantine (e.g., E:\\payload.vbs)."
                    },
                    "reason": {
                        "type": "string",
                        "description": "Forensic justification for quarantine."
                    }
                },
                "required": ["file_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "quarantine_matching",
            "description": "Quarantines all files matching a specific risk criterion (e.g., 'double_extension', 'high_entropy', 'malicious', 'all_threats').",
            "parameters": {
                "type": "object",
                "properties": {
                    "criteria": {
                        "type": "string",
                        "enum": ["double_extension", "high_entropy", "malicious", "all_threats", "hidden_scripts"],
                        "description": "The category of suspicious files to quarantine."
                    }
                },
                "required": ["criteria"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "calculate_entropy",
            "description": "Calculates Shannon Entropy and inspects byte distribution for a specific physical file on the USB.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "The path to the file to inspect."
                    }
                },
                "required": ["file_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_hidden_artifacts",
            "description": "Lists all hidden files, system files, and suspicious autorun artifacts found on the USB drive.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "export_pdf_report",
            "description": "Generates and exports an official USB Sentinel Forensic Investigation PDF report.",
            "parameters": {
                "type": "object",
                "properties": {
                    "destination_path": {
                        "type": "string",
                        "description": "Optional custom export path for the PDF."
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_file_with_ai",
            "description": "Performs deep AI forensic de-obfuscation and threat assessment on a specified file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to analyze."
                    }
                },
                "required": ["file_path"]
            }
        }
    }
]


class GroqAnalyzer:
    def __init__(self, api_key: str = None, model: str = None):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY") or DEFAULT_API_KEY
        self.model = model or DEFAULT_MODEL
        self.client = None
        self._init_client()

    def _init_client(self):
        try:
            if self.api_key:
                self.client = groq.Groq(api_key=self.api_key)
                # Verify if current model is valid; if not, automatically use first available chat model
                try:
                    avail = self.get_available_models()
                    if avail and self.model not in avail:
                        self.model = avail[0]
                except Exception:
                    pass
        except Exception as e:
            print(f"[Groq Analyzer] Initialization error: {e}")
            self.client = None

    def update_config(self, api_key: str, model: str = None):
        self.api_key = api_key
        if model:
            self.model = model
        self._init_client()

    def get_available_models(self) -> list[str]:
        """Queries Groq API for currently available models under this API key."""
        if not self.client:
            return [DEFAULT_MODEL] + FALLBACK_MODELS
        try:
            models_data = self.client.models.list()
            chat_models = [m.id for m in models_data.data if not ("whisper" in m.id or "guard" in m.id)]
            # Prioritize DEFAULT_MODEL if present
            ordered_models = []
            if DEFAULT_MODEL in chat_models:
                ordered_models.append(DEFAULT_MODEL)
            for m in chat_models:
                if m not in ordered_models:
                    ordered_models.append(m)
            return ordered_models if ordered_models else [self.model]
        except Exception as e:
            print(f"[Groq Analyzer] Failed to fetch models: {e}")
            return [self.model] + FALLBACK_MODELS

    def _execute_completion_with_fallback(self, **kwargs) -> Any:
        """
        Executes a Groq chat completion. If chosen model fails (not found, rate limit,
        or validation error), automatically cascades to available fallback models.
        """
        if not self.client:
            raise RuntimeError("Groq API client is not initialized. Please verify your API key.")

        # Dynamically retrieve verified models for this API key
        avail = []
        try:
            avail = self.get_available_models()
        except Exception:
            pass

        models_to_try = []
        # Add current model if valid
        if self.model and (not avail or self.model in avail):
            models_to_try.append(self.model)

        for m in (avail or FALLBACK_MODELS):
            if m not in models_to_try:
                models_to_try.append(m)

        # If calling tools, filter strictly to models that support tool calling on Groq
        if "tools" in kwargs and kwargs["tools"] is not None:
            models_to_try = [m for m in models_to_try if m in ["qwen/qwen3.8-27b", "openai/gpt-oss-120b", "openai/gpt-oss-20b"]]
            if not models_to_try:
                models_to_try = ["qwen/qwen3.8-27b", "openai/gpt-oss-120b"]

        if not models_to_try:
            models_to_try = [DEFAULT_MODEL]

        last_error = None
        for m in models_to_try:
            try:
                call_kwargs = dict(kwargs)
                call_kwargs["model"] = m
                return self.client.chat.completions.create(**call_kwargs)
            except groq.AuthenticationError as e:
                # Invalid API key cannot be fixed by switching models
                raise e
            except Exception as e:
                last_error = e
                print(f"[Groq Analyzer] Model '{m}' encountered error: {e}. Trying fallback...")
                continue

        raise last_error or RuntimeError("All model fallback attempts failed.")

    def analyze_suspicious_file(self, file_data: dict) -> dict:
        """
        Feature 3A: Automated AI Deep Forensic Analysis.
        Sends file metadata, cryptographic hashes, entropy, and extracted strings
        to Groq with response_format={"type": "json_object"}.
        """
        if not self.client:
            return {
                "threat_verdict": "Unavailable",
                "threat_score": file_data.get("threat_score", 50),
                "malware_category": "Unchecked (API Key Missing)",
                "mitre_att_ck": [],
                "deobfuscated_summary": "Groq client is not initialized. Configure API key in Settings.",
                "recommended_action": "Quarantine" if file_data.get("threat_score", 0) >= 60 else "Allow"
            }

        # Format compact input payload (< 350 tokens) to guarantee zero 413 rate limit errors
        raw_strings = file_data.get("extracted_strings_sample", [])
        sampled_strings = [str(s)[:100] for s in raw_strings[:8]]
        
        prompt_payload = {
            "file_name": file_data.get("name"),
            "extension": file_data.get("extension"),
            "size_bytes": file_data.get("size_bytes"),
            "md5": file_data.get("md5"),
            "sha256": file_data.get("sha256"),
            "entropy": round(float(file_data.get("entropy", 0.0)), 2),
            "magic_desc": str(file_data.get("magic_desc") or "")[:80],
            "is_hidden": bool(file_data.get("is_hidden")),
            "heuristic_alerts": [str(a)[:80] for a in file_data.get("rules_triggered", [])[:4]],
            "extracted_strings_sample": sampled_strings
        }

        system_prompt = (
            "You are USB Sentinel AI, a world-class digital forensics and malware reverse-engineering expert.\n"
            "Analyze the following USB file metadata and extracted strings for obfuscation, deceptive naming, payload staging, and malicious intent.\n"
            "You MUST respond ONLY with a single valid JSON object strictly matching this schema:\n"
            "{\n"
            '  "threat_verdict": "Malicious",\n'
            '  "threat_score": 85,\n'
            '  "malware_category": "Trojan Dropper",\n'
            '  "mitre_att_ck": ["T1059.001 - PowerShell", "T1027 - Obfuscated Files"],\n'
            '  "deobfuscated_summary": "Concise forensic summary of what this code/binary attempts to execute.",\n'
            '  "recommended_action": "Quarantine"\n'
            "}\n\n"
            "CRITICAL INSTRUCTIONS:\n"
            "1. 'threat_verdict': Strictly choose one of: 'Malicious', 'High Risk', 'Suspicious', 'Clean'.\n"
            "2. 'threat_score': Integer from 0 to 100 representing risk level.\n"
            "3. 'mitre_att_ck': Array of at most 3 to 5 most relevant MITRE ATT&CK techniques. Do NOT produce long lists or sub-technique permutations.\n"
            "4. 'deobfuscated_summary': A direct, clear forensic explanation in 2 to 4 sentences.\n"
            "5. 'recommended_action': Strictly choose one of: 'Quarantine', 'Delete', 'Allow', 'Sandbox'.\n"
            "6. Output strictly valid JSON without markdown code blocks."
        )

        try:
            response = self._execute_completion_with_fallback(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": json.dumps(prompt_payload, indent=2)}
                ],
                response_format={"type": "json_object"},
                temperature=0.1
            )
            raw_json = response.choices[0].message.content.strip()
            if raw_json.startswith("```json"):
                raw_json = raw_json[7:]
            if raw_json.startswith("```"):
                raw_json = raw_json[3:]
            if raw_json.endswith("```"):
                raw_json = raw_json[:-3]
            raw_json = raw_json.strip()

            parsed = json.loads(raw_json)

            # Normalize possible key variations
            if "mitre_att_ck" not in parsed:
                for alt in ["mitre_attack_techniques", "mitre_techniques", "mitre", "attack_techniques"]:
                    if alt in parsed:
                        parsed["mitre_att_ck"] = parsed.pop(alt)
                        break
            if not isinstance(parsed.get("mitre_att_ck"), list):
                parsed["mitre_att_ck"] = [str(parsed.get("mitre_att_ck"))] if parsed.get("mitre_att_ck") else []

            # Limit MITRE techniques to top 5
            parsed["mitre_att_ck"] = [str(item) for item in parsed["mitre_att_ck"][:5]]

            if "threat_verdict" not in parsed:
                parsed["threat_verdict"] = parsed.get("verdict", "Suspicious")

            if "deobfuscated_summary" not in parsed:
                for alt in ["summary", "intent_analysis", "analysis"]:
                    if alt in parsed:
                        parsed["deobfuscated_summary"] = parsed.pop(alt)
                        break
                if "deobfuscated_summary" not in parsed:
                    parsed["deobfuscated_summary"] = "Forensic inspection completed."

            try:
                parsed["threat_score"] = int(parsed.get("threat_score", file_data.get("threat_score", 50)))
            except (ValueError, TypeError):
                parsed["threat_score"] = file_data.get("threat_score", 50)

            if "recommended_action" not in parsed:
                parsed["recommended_action"] = "Quarantine" if parsed["threat_score"] >= 60 else "Allow"

            return parsed
        except Exception as e:
            print(f"[Groq Analyzer] Deep analysis error: {e}")
            score = file_data.get("threat_score", 50)
            heuristics = file_data.get("rules_triggered", [])
            is_mal = score >= 60 or bool(heuristics)
            return {
                "threat_verdict": "High Risk" if score >= 75 else ("Suspicious" if is_mal else "Clean"),
                "threat_score": score,
                "malware_category": "Heuristic Threat Assessment",
                "mitre_att_ck": [f"Triggered Rule: {h}" for h in heuristics[:3]] if heuristics else ["T1204 - User Execution"],
                "deobfuscated_summary": (
                    f"AI analysis could not complete ({str(e)}). "
                    f"Static forensic engine calculated a threat score of {score}/100. "
                    f"Triggered heuristic rules: {', '.join(heuristics) if heuristics else 'None detected'}."
                ),
                "recommended_action": "Quarantine" if is_mal else "Allow"
            }

    def chat_intent(
        self,
        user_message: str,
        conversation_history: list,
        context_data: dict,
        tool_executor: Callable[[str, dict], dict] = None
    ) -> tuple[str, list]:
        """
        Feature 3B: Natural Language AI Intent Assistant with Tool Calling.
        Processes user query, invokes tools if necessary, and returns final answer.
        """
        if not self.client:
            return "Groq AI is currently offline. Please configure your API key in Settings.", []

        # Build compact context summary (< 350 tokens) to prevent 413 token limit errors
        compact_ctx = {
            "device": context_data.get("device_name") or context_data.get("device", {}).get("device_name", "USB Drive"),
            "mount": context_data.get("mount_point") or context_data.get("device", {}).get("mount_point", "E:\\"),
            "scanned": context_data.get("total_files_scanned", 0),
            "threats": context_data.get("threat_summary", {}),
            "flagged_files": [
                {
                    "name": f.get("name"),
                    "path": f.get("path"),
                    "score": f.get("threat_score"),
                    "rules": f.get("rules", [])[:2]
                }
                for f in context_data.get("suspicious_files", [])[:8]
            ]
        }

        system_content = (
            "You are the USB Sentinel AI Forensics Copilot assisting digital forensics investigators.\n"
            "You have tools to perform real actions: quarantining files, calculating entropy, listing hidden artifacts, or generating reports.\n"
            f"CURRENT USB FORENSIC CONTEXT:\n{json.dumps(compact_ctx)}\n\n"
            "If the user requests an action (e.g. quarantine, entropy, report), call the appropriate tool.\n"
            "Be concise, professional, and explain forensic findings directly."
        )

        messages = [{"role": "system", "content": system_content}]
        messages.extend(conversation_history)
        messages.append({"role": "user", "content": user_message})

        executed_actions = []

        try:
            # First turn: model decides whether to call a tool
            response = self._execute_completion_with_fallback(
                messages=messages,
                tools=FORENSIC_TOOLS,
                tool_choice="auto",
                temperature=0.3
            )
            choice = response.choices[0]
            msg = choice.message

            # Check if tools were called
            if msg.tool_calls:
                # Add assistant message with tool calls to history
                messages.append(msg)

                for tool_call in msg.tool_calls:
                    fn_name = tool_call.function.name
                    try:
                        args = json.loads(tool_call.function.arguments)
                    except Exception:
                        args = {}

                    # Execute tool via callback
                    tool_result = {"status": "error", "message": "No tool executor attached"}
                    if tool_executor:
                        tool_result = tool_executor(fn_name, args)

                    executed_actions.append({
                        "tool": fn_name,
                        "arguments": args,
                        "result": tool_result
                    })

                    # Add tool response message
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps(tool_result)
                    })

                # Second turn: model explains results to user
                final_response = self._execute_completion_with_fallback(
                    messages=messages,
                    temperature=0.3
                )
                final_text = final_response.choices[0].message.content
                return final_text, executed_actions

            else:
                return msg.content or "No response from AI.", executed_actions

        except Exception as e:
            return f"AI Copilot encountered an error: {str(e)}", executed_actions
