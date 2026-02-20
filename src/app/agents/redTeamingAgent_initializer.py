# Azure imports
from azure.identity import DefaultAzureCredential
from azure.ai.evaluation.red_team import RedTeam, RiskCategory, AttackStrategy
from pyrit.prompt_target import OpenAIChatTarget
import os
import asyncio
import json
from dotenv import load_dotenv
load_dotenv()

# Azure AI Project Information
azure_ai_project = os.getenv("FOUNDRY_ENDPOINT")
gpt_endpoint = os.getenv("gpt_endpoint")
gpt_deployment = os.getenv("gpt_deployment")
gpt_api_key = os.getenv("gpt_api_key")
gpt_api_version = os.getenv("gpt_api_version")

required_env = {
    "FOUNDRY_ENDPOINT": azure_ai_project,
    "gpt_endpoint": gpt_endpoint,
    "gpt_deployment": gpt_deployment,
    "gpt_api_key": gpt_api_key,
    "gpt_api_version": gpt_api_version,
}
missing_env = [name for name, value in required_env.items() if not value]
if missing_env:
    raise ValueError(f"Missing required environment variables: {', '.join(missing_env)}")

# Instantiate your AI Red Teaming Agent
# red_team_agent = RedTeam(
#     azure_ai_project=azure_ai_project,
#     credential=DefaultAzureCredential(),
#     risk_categories=[
#         RiskCategory.Violence,
#         RiskCategory.HateUnfairness,
#         RiskCategory.Sexual,
#         RiskCategory.SelfHarm
#     ],
#     num_objectives=5,
# )

red_team_agent = RedTeam(
    azure_ai_project=azure_ai_project,
    credential=DefaultAzureCredential(),
    custom_attack_seed_prompts="data/custom_attack_prompts.json",
    risk_categories=[
        RiskCategory.Violence,
        RiskCategory.SelfHarm
     ],
    num_objectives=12,
)


# Configuration for Azure OpenAI model
chat_target = OpenAIChatTarget(
    model_name=gpt_deployment,
    endpoint=f"{gpt_endpoint}/openai/deployments/{gpt_deployment}/chat/completions",
    api_key=gpt_api_key,
    api_version=gpt_api_version,
)


def print_scan_summary(result) -> None:
    if hasattr(result, "model_dump"):
        result_data = result.model_dump()
    elif isinstance(result, dict):
        result_data = result
    else:
        result_data = getattr(result, "__dict__", {})

    scorecard_raw = result_data.get("scorecard", {})
    if hasattr(scorecard_raw, "model_dump"):
        scorecard = scorecard_raw.model_dump()
    elif isinstance(scorecard_raw, dict):
        scorecard = scorecard_raw
    else:
        scorecard = getattr(scorecard_raw, "__dict__", {})

    category_summary = (scorecard.get("risk_category_summary") or [{}])[0]
    technique_summary = (scorecard.get("attack_technique_summary") or [{}])[0]

    violence_asr = category_summary.get("violence_asr", 0.0) * 100
    self_harm_asr = category_summary.get("self_harm_asr", 0.0) * 100
    overall_asr = category_summary.get("overall_asr", 0.0) * 100

    print("\n=== Red Team Scan Summary ===")
    print(f"Overall ASR: {overall_asr:.2f}%")
    print(f"Violence ASR: {violence_asr:.2f}%")
    print(f"Self-Harm ASR: {self_harm_asr:.2f}%")
    print(f"Total attacks: {category_summary.get('overall_total', 0)}")
    print(f"Successful attacks: {category_summary.get('overall_successful_attacks', 0)}")
    print(f"Baseline ASR: {technique_summary.get('baseline_asr', 0.0) * 100:.2f}%")
    print(f"Easy ASR: {technique_summary.get('easy_asr', 0.0) * 100:.2f}%")
    print(f"Moderate ASR: {technique_summary.get('moderate_asr', 0.0) * 100:.2f}%")


async def main():
    red_team_result = await red_team_agent.scan(
        target=chat_target,
        scan_name="Red Team Scan - Strict Custom Seeds",
        attack_strategies=[
            AttackStrategy.Baseline,
            AttackStrategy.Flip,
            AttackStrategy.ROT13,
            AttackStrategy.Base64,
            AttackStrategy.AnsiAttack,
            AttackStrategy.Tense
        ])

    if isinstance(red_team_result, str):
        try:
            parsed_result = json.loads(red_team_result)
        except json.JSONDecodeError:
            print("Scan completed but result was not JSON serializable.")
            return
    elif hasattr(red_team_result, "model_dump"):
        parsed_result = red_team_result.model_dump()
    else:
        parsed_result = red_team_result

    print_scan_summary(parsed_result)


asyncio.run(main())
