import requests
import json
import time
from datetime import datetime
import os
import openai
import uuid
from dotenv import load_dotenv
from flask import Flask, jsonify, Response, stream_template
from flask_cors import CORS

# Load environment variables from .env file
load_dotenv()

# Set OpenAI API key from environment variable
openai.api_key = os.getenv('OPENAI_API_KEY')

# Initialize Flask app
app = Flask(__name__)
CORS(app, origins=["*"], methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# Session setup
session = requests.Session()

# Set your preferred headers here (you can also rotate if needed)
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json, text/plain, */*",
    "x-user": "9"
}

# Base URL
base_url = "https://staging-v2.gradientcyber.net/quorum/api"

# Define the system instruction as a constant
SYSTEM_INSTRUCTION = """NIST 2.0 AI Recommendation Engine (Simplified Output Version)

You are a senior cybersecurity consultant specializing in NIST Cybersecurity Framework 2.0 and MXDR (Managed Extended Detection and Response) capabilities. You will analyze subcategory-level input from a NIST-based assessment and generate focused, actionable, and compact recommendations to guide remediation efforts.

---

## INPUT FORMAT

You will be given for each subcategory:
- Subcategory ID and Title
- NIST Category (e.g., GOVERN, PROTECT)
- Current Score (0–5)
- User Response (textual context about their current state)
- Additional context and informative references (optional)
- Overall maturity scores per NIST category

Example Input:
ID.GV-01 (Governance):
Score: 2
Response: "We have some policies, but they are informal and not consistently followed."

PR.PT-03 (Protective Technology - Network Segmentation):
Score: 0
Response: "We do not use network segmentation or isolation to protect critical systems."

RS.MI-01 (Mitigation Improvements):
Score: 3
Response: "We occasionally update our response plans based on lessons learned from incidents."

Reference a curated knowledge base of:
- NIST CSF control descriptions
- Actionable remediation steps
- MXDR platform capabilities

---

## OUTPUT FORMAT

Return a single JSON object per subcategory with only the following fields:

{
  "subcategory": "[NIST subcategory ID]",
  "title": "[Full subcategory title]",
  "description": "[Brief subcategory description]",
  "priority": "[Critical / High / Medium / Low]",
  "recommendation": "[Clear, concise remediation recommendation]",
  "rationale": "[Why this recommendation matters]",
  "supporting_resources": ["..."],
  "remediation_steps": [
    "Step 1",
    "Step 2",
    "Step 3"
  ],
  "tools": ["Tool A", "Tool B"],
  "references": ["NIST or industry references"],
  "effort_level": "[Low / Medium / High]",
  "impact_score": [1–10],
  "reference_note": "Reference a curated knowledge base of: NIST CSF control descriptions, actionable remediation steps, and MXDR platform capabilities."
}

---

## RULES

- Output must be a clean JSON object only — no extra text.
- All fields must be present and contain useful, specific, real-world information.
- Do not include placeholder values or explain the response format.
- Prioritize clarity and executive relevance.
- Align recommendations with NIST intent, best practices, and realistic implementation constraints.

---

## PRIORITY RULES

- Critical: Score 0–1 (foundational gap)
- High: Score 2 (significant gap)
- Medium: Score 3 (moderate maturity)
- Low: Score 4–5 (fine-tuning opportunity)

---

Your goal is to guide strategic remediation aligned to NIST CSF and promote MXDR capabilities where applicable. Focus on value, feasibility, and measurable improvement.
"""

# Helper Functions
def generate_summary_insight(percentage_scores):
    """
    Generate a summary insight based on average percentage score.
    """
    if not percentage_scores:
        return "No scores available to analyze."
    avg_score = sum(percentage_scores.values()) / len(percentage_scores)
    if avg_score >= 76:
        return "Organization demonstrates strong cybersecurity practices across all categories."
    elif avg_score >= 51:
        return "Organization shows moderate cybersecurity implementation with some areas needing improvement."
    elif avg_score >= 26:
        return "Organization has basic cybersecurity measures in place but requires significant improvements."
    else:
        return "Organization lacks comprehensive cybersecurity implementation across all categories."

def determine_priority_by_percentage(percentage_score):
    """
    Determine priority based on percentage performance (0-100%)
    """
    if percentage_score == 0:
        return "Critical"           # 0% - No implementation
    elif percentage_score <= 25:
        return "Critical"           # 1-25% - Minimal implementation  
    elif percentage_score <= 50:
        return "High"              # 26-50% - Basic implementation
    elif percentage_score <= 75:
        return "Medium"            # 51-75% - Good implementation
    else:
        return "Low"               # 76-100% - Excellent (optimization focus)

def generate_recommendation(category, score):
    """
    Generate specific recommendations based on category and score.
    """
    recommendations = {
        "govern": {
            0: "Implement basic governance framework and policies",
            1: "Develop formal governance documentation and procedures",
            2: "Strengthen and formalize existing governance practices",
            3: "Optimize governance processes and ensure organization-wide adoption"
        },
        "identify": {
            0: "Establish basic asset management and risk assessment processes",
            1: "Develop comprehensive asset inventory and risk management program",
            2: "Enhance risk assessment and asset management practices",
            3: "Implement advanced risk management and asset tracking systems"
        },
        "protect": {
            0: "Implement basic protective measures and controls",
            1: "Develop comprehensive protection strategies",
            2: "Enhance existing protection mechanisms",
            3: "Optimize protection systems and controls"
        },
        "detect": {
            0: "Establish basic detection capabilities and monitoring",
            1: "Develop comprehensive detection systems",
            2: "Enhance detection and monitoring capabilities",
            3: "Implement advanced detection and analytics"
        },
        "respond": {
            0: "Create basic incident response procedures",
            1: "Develop formal incident response plan",
            2: "Enhance incident response capabilities",
            3: "Implement advanced incident response systems"
        },
        "recover": {
            0: "Establish basic recovery procedures",
            1: "Develop comprehensive recovery plans",
            2: "Enhance recovery capabilities",
            3: "Implement advanced recovery systems"
        }
    }
    
    return recommendations.get(category, {}).get(score, "Review and improve current practices")

def generate_rationale(category, score):
    """
    Generate rationale for recommendations based on category and score.
    """
    rationales = {
        "govern": {
            0: "No governance framework in place, creating significant compliance and operational risks",
            1: "Basic governance exists but needs formalization and broader implementation",
            2: "Governance practices are partially implemented but need strengthening",
            3: "Strong governance foundation exists, focus on optimization and continuous improvement"
        },
        "identify": {
            0: "Lack of asset management and risk assessment creates blind spots in security posture",
            1: "Basic identification processes exist but need expansion and formalization",
            2: "Moderate identification capabilities need enhancement for better coverage",
            3: "Advanced identification systems in place, focus on optimization"
        },
        "protect": {
            0: "No protective measures in place, leaving systems vulnerable to attacks",
            1: "Basic protection exists but needs expansion and formalization",
            2: "Moderate protection capabilities need enhancement",
            3: "Strong protection systems in place, focus on optimization"
        },
        "detect": {
            0: "No detection capabilities, unable to identify security incidents",
            1: "Basic detection systems exist but need improvement",
            2: "Moderate detection capabilities need enhancement",
            3: "Advanced detection systems in place, focus on optimization"
        },
        "respond": {
            0: "No incident response procedures, unable to handle security incidents effectively",
            1: "Basic response procedures exist but need formalization",
            2: "Moderate response capabilities need enhancement",
            3: "Advanced response systems in place, focus on optimization"
        },
        "recover": {
            0: "No recovery procedures, unable to restore operations after incidents",
            1: "Basic recovery procedures exist but need formalization",
            2: "Moderate recovery capabilities need enhancement",
            3: "Advanced recovery systems in place, focus on optimization"
        }
    }
    
    return rationales.get(category, {}).get(score, "Review current practices and identify improvement areas")

def get_supporting_resources(category):
    """
    Get relevant supporting resources for a category.
    """
    resources = {
        "govern": [
            "NIST Governance Framework Template",
            "Policy Implementation Guide",
            "Governance Maturity Assessment Tool"
        ],
        "identify": [
            "Asset Management Framework",
            "Risk Assessment Methodology Guide",
            "Critical Asset Identification Template"
        ],
        "protect": [
            "Security Control Implementation Guide",
            "Access Control Framework",
            "Data Protection Best Practices"
        ],
        "detect": [
            "SIEM Implementation Guide",
            "Log Analysis Best Practices",
            "Threat Detection Framework"
        ],
        "respond": [
            "Incident Response Plan Template",
            "Response Playbook",
            "Incident Management Guide"
        ],
        "recover": [
            "Business Continuity Planning Guide",
            "Recovery Procedures Framework",
            "Disaster Recovery Template"
        ]
    }
    
    return resources.get(category, ["General cybersecurity best practices guide"])

def generate_next_steps(scores):
    """
    Generate prioritized next steps based on scores.
    """
    next_steps = []
    
    # Prioritize categories with lowest scores
    sorted_categories = sorted(scores.items(), key=lambda x: x[1])
    
    for category, score in sorted_categories:
        if score == 0:
            next_steps.append(f"Implement basic {category} measures and controls")
        elif score == 1:
            next_steps.append(f"Develop formal {category} processes and documentation")
        elif score == 2:
            next_steps.append(f"Enhance existing {category} practices")
    
    return next_steps

def analyze_individual_controls(survey_data):
    """
    Analyze individual NIST controls from the tasks array.
    """
    control_recommendations = []
    
    # Get tasks array
    tasks = survey_data.get("tasks", {}).get("tasks", [])
    
    for task in tasks:
        # Extract control ID from task name
        control_id = extract_control_id(task.get("name", ""))
        if not control_id:
            continue
            
        # Get score (treat null as 0)
        score = task.get("score", 0) or 0
        score = int(score)
        
        # Skip recommendation generation for scores 3, 4, 5 (good maturity levels)
        if score <= 2:
            # Generate control-specific recommendation
            recommendation = get_control_recommendation(control_id, score, task)
            control_recommendations.append(recommendation)
    
    return control_recommendations

def extract_control_id(task_name):
    """Extract control ID from task name"""
    if not task_name or ':' not in task_name:
        return None
    return task_name.split(':')[0].strip()

def get_control_recommendation(control_id, score, task_data):
    """
    Generate specific recommendations for individual controls.
    """
    # Default recommendation template
    recommendation = {
        "control_id": control_id,
        "priority": determine_priority(score),
        "current_score": score,
        "recommendation": "",
        "rationale": "",
        "supporting_resources": []
    }
    
    # Control-specific recommendations
    control_recommendations = {
        "GV.OC-01": {
            "recommendation": "Establish formal governance framework aligned with organizational mission",
            "rationale": "Governance framework ensures cybersecurity aligns with business objectives",
            "resources": ["NIST Governance Framework Template", "Mission Alignment Guide"]
        },
        "PR.AA-01": {
            "recommendation": "Implement comprehensive identity management system",
            "rationale": "Strong identity management is fundamental to access control",
            "resources": ["Identity Management Best Practices", "IAM Implementation Guide"]
        },
        "DE.AE-02": {
            "recommendation": "Deploy SIEM platform with threat intelligence integration",
            "rationale": "Advanced event analysis requires automated tools and threat intelligence",
            "resources": ["SIEM Implementation Guide", "Threat Intelligence Integration Guide"]
        },
        "RS.MA-01": {
            "recommendation": "Develop formal incident response procedures and playbooks",
            "rationale": "Structured response procedures ensure effective incident handling",
            "resources": ["Incident Response Plan Template", "Response Playbook Guide"]
        }
    }
    
    # Get control-specific recommendation if available
    if control_id in control_recommendations:
        recommendation.update(control_recommendations[control_id])
    else:
        # Generate generic recommendation based on control category
        category = control_id.split('.')[0] if '.' in control_id else ''
        recommendation["recommendation"] = f"Implement {category} control {control_id} according to NIST guidelines"
        recommendation["rationale"] = f"Control {control_id} is essential for {category} category implementation"
        recommendation["supporting_resources"] = [f"NIST {category} Control Implementation Guide"]
    
    return recommendation

def process_survey_data(survey_data):
    """Process survey data and generate recommendations"""
    # Extract percentage scores from meta data
    percentage_scores = survey_data.get("meta", {}).get("scores", {})
    
    # Generate analysis with both category and control-level recommendations
    analysis = {
        "summary_insight": generate_summary_insight(percentage_scores),
        "category_summaries": [],
        "individual_controls": [],
        "next_steps": []
    }
    
    # Generate category-level recommendations
    for category, percentage in percentage_scores.items():
        percentage = int(percentage)
        recommendation = {
            "category": category,
            "priority": determine_priority_by_percentage(percentage),
            "current_score": percentage,
            "current_percentage": f"{percentage}%",
            "recommendation": generate_recommendation(category, percentage),
            "rationale": generate_rationale(category, percentage),
            "supporting_resources": get_supporting_resources(category)
        }
        analysis["category_summaries"].append(recommendation)
    
    # Generate control-level recommendations
    analysis["individual_controls"] = analyze_individual_controls(survey_data)
    
    # Generate next steps based on both category and control analysis
    analysis["next_steps"] = generate_next_steps(percentage_scores)
    
    return analysis

def process_survey(survey_id):
   """Process a single survey and generate recommendations"""
   task_url = f"{base_url}/surveyTasks?surveyId={survey_id}"
   meta_url = f"{base_url}/survey?surveyId={survey_id}"
   print(f"\n🔄 Processing survey ID: {survey_id}")
   print(f"📡 Task URL: {task_url}")
   print(f"📡 Meta URL: {meta_url}")

   try:
       # Send both requests using session
       task_resp = session.get(task_url, headers=headers, timeout=30)
       meta_resp = session.get(meta_url, headers=headers, timeout=30)

       print(f"🛰️ Task Status: {task_resp.status_code} | Meta Status: {meta_resp.status_code}")

       task_data, meta_data = {}, {}

       # Handle meta response
       if meta_resp.status_code == 200 and meta_resp.text.strip():
           try:
               meta_data = meta_resp.json()
               if isinstance(meta_data.get("scores"), str):
                   try:
                       meta_data["scores"] = json.loads(meta_data["scores"])
                   except json.JSONDecodeError:
                       print(f"⚠️ Could not parse 'scores' for survey {survey_id}")
                       meta_data["scores"] = {}
           except json.JSONDecodeError as e:
               print(f"⚠️ Meta JSON error for survey {survey_id}: {e}")
       else:
           print(f"⚠️ Empty or non-JSON meta response for survey {survey_id}")

       # Handle task response
       if task_resp.status_code == 200 and task_resp.text.strip():
           try:
               task_data = task_resp.json()
           except json.JSONDecodeError as e:
               print(f"⚠️ Task JSON error for survey {survey_id}: {e}")
       else:
           print(f"⚠️ Empty or non-JSON task response for survey {survey_id}")

       # Create survey data
       survey_data = {
           "survey_id": survey_id,
           "meta": meta_data,
           "tasks": task_data
       }

       # Process the survey data and generate recommendations
       recommendations = []
       tasks = survey_data.get("tasks", {}).get("tasks", [])
       category_scores = survey_data.get("meta", {}).get("scores", {})

       for task in tasks:
           if task.get("score") is not None:
               score = int(task.get("score", 0))
               # Skip recommendation generation for scores 3, 4, 5 (good maturity levels)
               if score <= 2:
                   recommendation = generate_subcategory_recommendation(
                       task,
                       category_scores,
                       survey_id
                   )
                   if recommendation:
                       recommendations.append(recommendation)

       # Check if no recommendations were generated (all scores are 3+ indicating good maturity)
       if not recommendations:
           print("📊 No low-priority tasks found. Generating positive assessment message via LLM...")
           # Generate a positive assessment using LLM in the same format as recommendations
           positive_assessment = generate_positive_assessment_recommendation(category_scores, survey_id)
           if positive_assessment:
               recommendations = [positive_assessment]
           
       # Create the final output structure with recommendations (including positive assessment if applicable)
       final_output = {
           "user_context": {
               "survey_id": survey_id,
               "assessment_date": datetime.now().strftime("%Y-%m-%d"),
               "current_maturity_scores": category_scores,
               "overall_maturity_level": calculate_overall_maturity(category_scores)
           },
           "recommendations": recommendations
       }

       # Print the raw response
       print("\n📊 Generated Recommendations:")
       print(json.dumps(final_output, indent=2))
       
       print(f"✅ Processed: Survey {survey_id} at {datetime.now().strftime('%H:%M:%S')}")
       time.sleep(0.5)

       return final_output

   except requests.exceptions.RequestException as e:
       print(f"❌ Request failed for survey {survey_id}: {e}")
       return {"error": f"Request failed for survey {survey_id}: {str(e)}", "survey_id": survey_id}

def calculate_overall_maturity(category_scores):
    """Calculate overall maturity level based on category scores"""
    if not category_scores:
        return "Unknown"
    
    avg_score = sum(category_scores.values()) / len(category_scores)
    
    if avg_score >= 76:
        return "Advanced"
    elif avg_score >= 51:
        return "Intermediate"
    elif avg_score >= 26:
        return "Basic"
    else:
        return "Initial"

def get_score_response_text(score):
    """
    Get the descriptive text for a given score level.
    """
    score_responses = {
        0: "Incomplete. No formal practices exist.",
        1: "Ad hoc. Unstructured, reactive practices exist.",
        2: "Developing. Some policies and controls exist, but they are incomplete, inconsistent, or not widely followed.",
        3: "Managed. Policies and processes are documented, followed, and managed across teams, but effectiveness is not consistently measured.",
        4: "Quantified. Policies and controls are regularly measured and continuously improved. The organization has a structured cybersecurity approach.",
        5: "Optimized. Cybersecurity is fully integrated into business operations, continuously improving, and leveraging automation and advanced security practices."
    }
    return score_responses.get(score, "Unknown score level")

def generate_subcategory_recommendation(task, category_scores, survey_id):
    """Generate recommendation for a specific subcategory"""
    try:
        # Extract task information
        task_id = task.get("id")
        task_name = task.get("name", "")
        score = int(task.get("score", 0))
        category = task.get("kind", "").split()[0]  # Extract category from kind
        subcategory = task.get("subSystem", "")
        context = task.get("additionalContext", "")
        references = task.get("informativeReferences", "")
        
        # Get score response text for additional context
        score_response_text = get_score_response_text(score)

        # Determine priority
        priority = determine_priority(score)
        
        # Prepare the prompt for this subcategory
        prompt = prepare_subcategory_prompt(
            task_name,
            score,
            category,
            subcategory,
            context,
            references,
            category_scores,
            score_response_text
        )
        
        # Generate recommendation using GPT
        recommendation = generate_gpt_recommendation(prompt)
        
        if recommendation:
            # Add metadata
            recommendation.update({
                "nist_subcategory": task_id,
                "subcategory_title": task_name,
                "category": category,
                "current_score": score,
                "score_response": score_response_text,
                "priority": priority,
                "recommendation_id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat()
            })
            
            return recommendation
            
    except Exception as e:
        print(f"Error generating recommendation for task {task.get('id')}: {e}")
        return None

def determine_priority(score):
    """Determine priority based on score"""
    if score <= 1:
        return "Critical"
    elif score == 2:
        return "High"
    elif score == 3:
        return "Medium"
    else:
        return "Low"

def prepare_subcategory_prompt(task_name, score, category, subcategory, context, references, category_scores, score_response_text):
    """Prepare the prompt for a specific subcategory"""
    return f"""
    Generate a comprehensive NIST 2.0 recommendation for:
    
    Subcategory: {task_name}
    Current Score: {score}
    Score Description: {score_response_text}
    Category: {category}
    Subcategory: {subcategory}
    
    Current Maturity Scores:
    {json.dumps(category_scores, indent=2)}
    
    Additional Context from User:
    {context}
    
    References:
    {references}
    
    Please provide a recommendation following the specified JSON structure, ensuring:
    1. All recommendations are actionable and specific
    2. MXDR services are mapped according to the provided pricing tiers
    3. Implementation timelines are realistic
    4. Business rationale is compelling and specific
    5. Technical recommendations align with NIST examples
    6. ROI calculations use industry-standard metrics
    7. Language is professional but accessible to executives
    8. Recommendations specifically address the current maturity level described in the Score Description.
    """

def generate_positive_assessment_recommendation(category_scores, survey_id):
    """Generate a positive assessment recommendation when no improvements are needed"""
    try:
        # Create prompt for positive assessment
        prompt = f"""
        Generate a positive cybersecurity assessment for an organization with strong maturity scores.
        
        Current Maturity Scores:
        {json.dumps(category_scores, indent=2)}
        
        Survey ID: {survey_id}
        Assessment Context: All cybersecurity controls scored 3 or higher, indicating well-established practices.
        
        Create a congratulatory recommendation that:
        1. Acknowledges their strong cybersecurity posture
        2. Provides guidance for maintaining excellence
        3. Suggests optimization and continuous improvement
        
        Use subcategory "OVERALL-ASSESSMENT" and title "Cybersecurity Excellence Achieved".
        Set priority to "Low" since no urgent actions are needed.
        Focus on maintenance, monitoring, and strategic improvements.
        """
        
        # Generate recommendation using GPT
        recommendation = generate_gpt_recommendation(prompt)
        
        if recommendation:
            # Add metadata for positive assessment
            recommendation.update({
                "assessment_type": "positive_evaluation",
                "recommendation_id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat()
            })
            
            return recommendation
            
    except Exception as e:
        print(f"Error generating positive assessment: {e}")
        # Fallback to a basic positive message if LLM fails
        return {
            "subcategory": "OVERALL-ASSESSMENT",
            "title": "Cybersecurity Excellence Achieved",
            "description": "Organization demonstrates strong cybersecurity maturity across all assessed areas",
            "priority": "Low",
            "recommendation": "Congratulations! Your cybersecurity controls are well-established and working effectively. Continue monitoring and optimizing your security posture.",
            "rationale": "All assessed areas show strong maturity levels, indicating effective cybersecurity implementation",
            "supporting_resources": ["Continuous Monitoring Guide", "Security Optimization Best Practices"],
            "remediation_steps": [
                "Continue regular security assessments",
                "Monitor for emerging threats and technologies", 
                "Optimize existing controls for efficiency"
            ],
            "tools": ["Security Monitoring Platforms", "Threat Intelligence Services"],
            "references": ["NIST Cybersecurity Framework", "Security Excellence Guidelines"],
            "effort_level": "Low",
            "impact_score": 8,
            "assessment_type": "positive_evaluation",
            "recommendation_id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat()
        }

def generate_gpt_recommendation(prompt, retries=3, delay=10):
    """Generate recommendation using GPT"""
    for attempt in range(retries):
        try:
            client = openai.OpenAI()
            response = client.chat.completions.create(
                model="gpt-4o-mini",  
                messages=[
                    {"role": "system", "content": SYSTEM_INSTRUCTION},
                    {"role": "user", "content": prompt}
                ],
                temperature=0,
                max_tokens=4000
            )
            content = response.choices[0].message.content
            if not content.strip():
                print("Empty response from model!")
                return None
            try:
                recommendation = json.loads(content)
                return recommendation
            except json.JSONDecodeError:
                print("Model did not return valid JSON:", content)
                continue
        except Exception as e:
            print(f"Error generating GPT recommendation (attempt {attempt+1}): {e}")
            if attempt < retries - 1:
                time.sleep(delay)
    return None

@app.route('/')
def home():
    return "NIST 2.0 Recommendation Engine API is running"

@app.route('/process_survey/<survey_id>')
def process_survey_endpoint(survey_id):
    try:
        survey_id = int(survey_id)
        result = process_survey(survey_id)
        return jsonify(result)
    except ValueError:
        return jsonify({"error": "Invalid survey ID. Must be a number."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/process_survey_stream/<survey_id>')
def process_survey_stream_endpoint(survey_id):
    """Streaming endpoint that yields recommendations as they are generated"""
    try:
        survey_id = int(survey_id)
        
        def generate():
            """Generator function that yields streaming data"""
            # Send initial status
            yield f"data: {json.dumps({'type': 'status', 'message': 'Starting survey processing...', 'survey_id': survey_id})}\n\n"
            
            # Fetch survey data
            task_url = f"{base_url}/surveyTasks?surveyId={survey_id}"
            meta_url = f"{base_url}/survey?surveyId={survey_id}"
            
            yield f"data: {json.dumps({'type': 'status', 'message': 'Fetching survey data...'})}\n\n"
            
            try:
                # Send both requests using session
                task_resp = session.get(task_url, headers=headers, timeout=30)
                meta_resp = session.get(meta_url, headers=headers, timeout=30)
                
                yield f"data: {json.dumps({'type': 'status', 'message': f'API Status - Task: {task_resp.status_code}, Meta: {meta_resp.status_code}'})}\n\n"
                
                task_data, meta_data = {}, {}
                
                # Handle meta response
                if meta_resp.status_code == 200 and meta_resp.text.strip():
                    try:
                        meta_data = meta_resp.json()
                        if isinstance(meta_data.get("scores"), str):
                            try:
                                meta_data["scores"] = json.loads(meta_data["scores"])
                            except json.JSONDecodeError:
                                yield f"data: {json.dumps({'type': 'warning', 'message': 'Could not parse scores data'})}\n\n"
                                meta_data["scores"] = {}
                    except json.JSONDecodeError as e:
                        yield f"data: {json.dumps({'type': 'warning', 'message': f'Meta JSON error: {str(e)}'})}\n\n"
                else:
                    yield f"data: {json.dumps({'type': 'warning', 'message': 'Empty or non-JSON meta response'})}\n\n"
                
                # Handle task response
                if task_resp.status_code == 200 and task_resp.text.strip():
                    try:
                        task_data = task_resp.json()
                    except json.JSONDecodeError as e:
                        yield f"data: {json.dumps({'type': 'warning', 'message': f'Task JSON error: {str(e)}'})}\n\n"
                else:
                    yield f"data: {json.dumps({'type': 'warning', 'message': 'Empty or non-JSON task response'})}\n\n"
                
                # Create survey data
                survey_data = {
                    "survey_id": survey_id,
                    "meta": meta_data,
                    "tasks": task_data
                }
                
                # Send user context
                category_scores = survey_data.get("meta", {}).get("scores", {})
                user_context = {
                    "survey_id": survey_id,
                    "assessment_date": datetime.now().strftime("%Y-%m-%d"),
                    "current_maturity_scores": category_scores,
                    "overall_maturity_level": calculate_overall_maturity(category_scores)
                }
                
                yield f"data: {json.dumps({'type': 'user_context', 'data': user_context})}\n\n"
                
                # Process tasks and generate recommendations
                tasks = survey_data.get("tasks", {}).get("tasks", [])
                # Only count tasks with scores 0, 1, 2 (skip good maturity levels 3, 4, 5)
                total_tasks = len([task for task in tasks if task.get("score") is not None and int(task.get("score", 0)) <= 2])
                processed_tasks = 0
                
                yield f"data: {json.dumps({'type': 'status', 'message': f'Processing {total_tasks} tasks...'})}\n\n"
                
                recommendations = []
                
                for task in tasks:
                    if task.get("score") is not None:
                        score = int(task.get("score", 0))
                        # Skip recommendation generation for scores 3, 4, 5 (good maturity levels)
                        if score <= 2:
                            processed_tasks += 1
                            
                            # Send progress update
                            progress = {
                                'type': 'progress',
                                'current': processed_tasks,
                                'total': total_tasks,
                                'percentage': round((processed_tasks / total_tasks) * 100, 1)
                            }
                            yield f"data: {json.dumps(progress)}\n\n"
                            
                            # Generate recommendation for this task
                            recommendation = generate_subcategory_recommendation(
                                task,
                                category_scores,
                                survey_id
                            )
                            
                            if recommendation:
                                recommendations.append(recommendation)
                                # Send individual recommendation
                                yield f"data: {json.dumps({'type': 'recommendation', 'data': recommendation})}\n\n"
                            
                            # Small delay to prevent overwhelming the client
                            time.sleep(0.1)
                
                # Send completion status
                yield f"data: {json.dumps({'type': 'status', 'message': 'Processing complete!'})}\n\n"
                
                # Check if no recommendations were generated and generate positive assessment
                if not recommendations:
                    yield f"data: {json.dumps({'type': 'status', 'message': 'Generating positive assessment via LLM...'})}\n\n"
                    positive_assessment = generate_positive_assessment_recommendation(category_scores, survey_id)
                    if positive_assessment:
                        recommendations = [positive_assessment]
                        yield f"data: {json.dumps({'type': 'recommendation', 'data': positive_assessment})}\n\n"
                
                # Send final summary
                final_summary = {
                    'type': 'summary',
                    'total_recommendations': len(recommendations),
                    'survey_id': survey_id,
                    'timestamp': datetime.now().isoformat()
                }
                yield f"data: {json.dumps(final_summary)}\n\n"
                
            except requests.exceptions.RequestException as e:
                error_msg = f"Request failed: {str(e)}"
                yield f"data: {json.dumps({'type': 'error', 'message': error_msg})}\n\n"
            except Exception as e:
                error_msg = f"Processing error: {str(e)}"
                yield f"data: {json.dumps({'type': 'error', 'message': error_msg})}\n\n"
            
            # Send end marker
            yield f"data: {json.dumps({'type': 'end'})}\n\n"
        
        return Response(generate(), mimetype='text/plain')
        
    except ValueError:
        return jsonify({"error": "Invalid survey ID. Must be a number."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/process_survey_sse/<survey_id>')
def process_survey_sse_endpoint(survey_id):
    """Server-Sent Events endpoint for real-time streaming to web clients"""
    try:
        survey_id = int(survey_id)
        
        def generate():
            """Generator function that yields SSE data"""
            # Send initial status
            yield f"data: {json.dumps({'type': 'status', 'message': 'Starting survey processing...', 'survey_id': survey_id})}\n\n"
            
            # Fetch survey data
            task_url = f"{base_url}/surveyTasks?surveyId={survey_id}"
            meta_url = f"{base_url}/survey?surveyId={survey_id}"
            
            yield f"data: {json.dumps({'type': 'status', 'message': 'Fetching survey data...'})}\n\n"
            
            try:
                # Send both requests using session
                task_resp = session.get(task_url, headers=headers, timeout=30)
                meta_resp = session.get(meta_url, headers=headers, timeout=30)
                
                yield f"data: {json.dumps({'type': 'status', 'message': f'API Status - Task: {task_resp.status_code}, Meta: {meta_resp.status_code}'})}\n\n"
                
                task_data, meta_data = {}, {}
                
                # Handle meta response
                if meta_resp.status_code == 200 and meta_resp.text.strip():
                    try:
                        meta_data = meta_resp.json()
                        if isinstance(meta_data.get("scores"), str):
                            try:
                                meta_data["scores"] = json.loads(meta_data["scores"])
                            except json.JSONDecodeError:
                                yield f"data: {json.dumps({'type': 'warning', 'message': 'Could not parse scores data'})}\n\n"
                                meta_data["scores"] = {}
                    except json.JSONDecodeError as e:
                        yield f"data: {json.dumps({'type': 'warning', 'message': f'Meta JSON error: {str(e)}'})}\n\n"
                else:
                    yield f"data: {json.dumps({'type': 'warning', 'message': 'Empty or non-JSON meta response'})}\n\n"
                
                # Handle task response
                if task_resp.status_code == 200 and task_resp.text.strip():
                    try:
                        task_data = task_resp.json()
                    except json.JSONDecodeError as e:
                        yield f"data: {json.dumps({'type': 'warning', 'message': f'Task JSON error: {str(e)}'})}\n\n"
                else:
                    yield f"data: {json.dumps({'type': 'warning', 'message': 'Empty or non-JSON task response'})}\n\n"
                
                # Create survey data
                survey_data = {
                    "survey_id": survey_id,
                    "meta": meta_data,
                    "tasks": task_data
                }
                
                # Send user context
                category_scores = survey_data.get("meta", {}).get("scores", {})
                user_context = {
                    "survey_id": survey_id,
                    "assessment_date": datetime.now().strftime("%Y-%m-%d"),
                    "current_maturity_scores": category_scores,
                    "overall_maturity_level": calculate_overall_maturity(category_scores)
                }
                
                yield f"data: {json.dumps({'type': 'user_context', 'data': user_context})}\n\n"
                
                # Process tasks and generate recommendations
                tasks = survey_data.get("tasks", {}).get("tasks", [])
                # Only count tasks with scores 0, 1, 2 (skip good maturity levels 3, 4, 5)
                total_tasks = len([task for task in tasks if task.get("score") is not None and int(task.get("score", 0)) <= 2])
                processed_tasks = 0
                
                yield f"data: {json.dumps({'type': 'status', 'message': f'Processing {total_tasks} tasks...'})}\n\n"
                
                recommendations = []
                
                for task in tasks:
                    if task.get("score") is not None:
                        score = int(task.get("score", 0))
                        # Skip recommendation generation for scores 3, 4, 5 (good maturity levels)
                        if score <= 2:
                            processed_tasks += 1
                            
                            # Send progress update
                            progress = {
                                'type': 'progress',
                                'current': processed_tasks,
                                'total': total_tasks,
                                'percentage': round((processed_tasks / total_tasks) * 100, 1)
                            }
                            yield f"data: {json.dumps(progress)}\n\n"
                            
                            # Generate recommendation for this task
                            recommendation = generate_subcategory_recommendation(
                                task,
                                category_scores,
                                survey_id
                            )
                            
                            if recommendation:
                                recommendations.append(recommendation)
                                # Send individual recommendation
                                yield f"data: {json.dumps({'type': 'recommendation', 'data': recommendation})}\n\n"
                            
                            # Small delay to prevent overwhelming the client
                            time.sleep(0.1)
                
                # Send completion status
                yield f"data: {json.dumps({'type': 'status', 'message': 'Processing complete!'})}\n\n"
                
                # Check if no recommendations were generated and generate positive assessment
                if not recommendations:
                    yield f"data: {json.dumps({'type': 'status', 'message': 'Generating positive assessment via LLM...'})}\n\n"
                    positive_assessment = generate_positive_assessment_recommendation(category_scores, survey_id)
                    if positive_assessment:
                        recommendations = [positive_assessment]
                        yield f"data: {json.dumps({'type': 'recommendation', 'data': positive_assessment})}\n\n"
                
                # Send final summary
                final_summary = {
                    'type': 'summary',
                    'total_recommendations': len(recommendations),
                    'survey_id': survey_id,
                    'timestamp': datetime.now().isoformat()
                }
                yield f"data: {json.dumps(final_summary)}\n\n"
                
            except requests.exceptions.RequestException as e:
                error_msg = f"Request failed: {str(e)}"
                yield f"data: {json.dumps({'type': 'error', 'message': error_msg})}\n\n"
            except Exception as e:
                error_msg = f"Processing error: {str(e)}"
                yield f"data: {json.dumps({'type': 'error', 'message': error_msg})}\n\n"
            
            # Send end marker
            yield f"data: {json.dumps({'type': 'end'})}\n\n"
        
        return Response(generate(), mimetype='text/event-stream', headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Cache-Control'
        })
        
    except ValueError:
        return jsonify({"error": "Invalid survey ID. Must be a number."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("Starting NIST 2.0 Recommendation Engine API on http://localhost:5000")
    print("Available endpoints:")
    print("  GET /process_survey/<survey_id> - Process survey and return complete result")
    print("  GET /process_survey_stream/<survey_id> - Stream recommendations as they're generated")
    print("  GET /process_survey_sse/<survey_id> - Server-Sent Events for real-time web streaming")
    app.run(host='0.0.0.0', port=5000, debug=True)
