#!/usr/bin/env python3

import re
import sys
import getpass
from typing import List, Tuple

class PasswordChecker:
    def __init__(self):
        self.min_length = 8
        self.requirements = [
            (r'[A-Z]', 'uppercase letter'),
            (r'[a-z]', 'lowercase letter'),
            (r'[0-9]', 'number'),
            (r'[!@#$%^&*(),.?":{}|<>]', 'special character'),
        ]

    def check_strength(self, password: str) -> Tuple[int, List[str]]:
        """
        Check password strength and return a score (0-100) and list of missing requirements.
        """
        score = 0
        missing = []
        
        # Length check
        if len(password) < self.min_length:
            missing.append(f"at least {self.min_length} characters")
        else:
            score += 20
        
        # Character type checks
        for pattern, requirement in self.requirements:
            if re.search(pattern, password):
                score += 20
            else:
                missing.append(requirement)
        
        # Additional complexity checks
        if len(set(password)) > 12:  # Character variety
            score += 10
        if len(password) > 12:  # Extra length bonus
            score += 10
            
        return min(score, 100), missing

    def get_recommendations(self, missing: List[str]) -> List[str]:
        """
        Generate specific recommendations based on missing requirements.
        """
        recommendations = []
        if missing:
            recommendations.append("Your password should include:")
            for req in missing:
                recommendations.append(f"- At least one {req}")
            recommendations.append("\nAdditional recommendations:")
            recommendations.append("- Avoid using personal information")
            recommendations.append("- Don't use common words or patterns")
            recommendations.append("- Use a unique password for each account")
        return recommendations

def main():
    checker = PasswordChecker()
    
    print("Password Strength Checker")
    print("------------------------")
    
    # Get password securely
    password = getpass.getpass("Enter password to check: ")
    
    # Check strength
    score, missing = checker.check_strength(password)
    
    # Display results
    print("\nPassword Strength Analysis:")
    print(f"Strength Score: {score}/100")
    
    if score < 60:
        print("Status: WEAK - Password needs improvement")
    elif score < 80:
        print("Status: MODERATE - Password could be stronger")
    else:
        print("Status: STRONG - Good password!")
    
    if missing:
        print("\nMissing Requirements:")
        for req in missing:
            print(f"- {req}")
    
    # Show recommendations
    recommendations = checker.get_recommendations(missing)
    if recommendations:
        print("\nRecommendations:")
        for rec in recommendations:
            print(rec)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0) 