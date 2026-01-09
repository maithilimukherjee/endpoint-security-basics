"""
evaluates password strength using length, character diversity,
and known weak patterns. returns a structured security assessment
including potential attack risks.
"""


import re

def check_strength(password):
    
    result = {
        "score":0,
        "rating":"",
        "issues":[],
        "attack_risks":[]
    }
    
    score = 0
    
    if len(password)<8:
        result["issues"].append("password is too short")
        result["attack_risks"].append("brute force attack")
        
    if len(password) >= 8:
        score += 20
    if len(password) >= 12:
        score += 10

        
    if re.search(r"[a-z]",password):
        score+=15
        
    else:
        result["issues"].append("missing lowercase letters")
    
    if re.search(r"[A-Z]",password):
        score+=15
        
    else:
        result["issues"].append("missing uppercase letters")

    if re.search(r"[0-9]", password):
        score += 15
    else:
        result["issues"].append("missing digits")

    if re.search(r"[^a-zA-Z0-9]", password):
        score += 15
    else:
        result["issues"].append("missing special characters")
    
    #common patterns
    
    common = ["12345678","11111111","password","123", "111", "password", "qwerty"]
    
    for pattern in common:
        
        if pattern in password.lower():
            score = score - 20
            result["attack_risks"].append("dictionary attack")
            break
    
    score = max(0,min(score,100))
    result["score"] = score
    
    #rating
    
    if score < 40:
        result["rating"] = "weak"
    elif score < 70:
        result["rating"] = "medium"
    else:
        result["rating"] = "strong"
        
    return result