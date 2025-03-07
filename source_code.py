import string
import matplotlib.pyplot as plt
import numpy as np

# Load Common Passwords List for Dictionary Attack
!wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt -O common_passwords.txt

# Load the passwords list from the downloaded file
with open("common_passwords.txt", "r", encoding="utf-8", errors="ignore") as file:
    COMMON_PASSWORDS = set(line.strip() for line in file)

# Function to check password strength
def password_strength(password):
    """
    Analyzes the strength of a given password based on length and character variety.
    
    Parameters:
        password (str): The input password.
    
    Returns:
        tuple: Strength category (str) and score (int)
    """
    length = len(password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char in string.punctuation for char in password)

    score = sum([has_upper, has_lower, has_digit, has_special])

    # Determine password strength based on length and score
    if length < 6:
        return "Very Weak", 1
    elif length < 8 or score < 2:
        return "Weak", 2
    elif length < 10 or score < 3:
        return "Medium", 3
    elif length >= 10 and score >= 3:
        return "Strong", 4
    elif length >= 12 and score == 4:
        return "Very Strong", 5

# Function to estimate brute force cracking time
def brute_force_time(password):
    """
    Estimates the time required to brute force a given password based on character space and length.
    
    Parameters:
        password (str): The input password.
    
    Returns:
        float: Estimated cracking time in seconds.
    """
    char_space = 0
    if any(c.islower() for c in password):
        char_space += 26
    if any(c.isupper() for c in password):
        char_space += 26
    if any(c.isdigit() for c in password):
        char_space += 10
    if any(c in string.punctuation for c in password):
        char_space += 32

    # Calculate total possible combinations
    combinations = char_space ** len(password)
    attempts_per_sec = 1e9  # Assume 1 billion attempts per second
    seconds_to_crack = combinations / attempts_per_sec
    return seconds_to_crack

# Function to check if the password is found in common passwords list
def dictionary_attack(password):
    """
    Checks if a password exists in a common leaked passwords list.
    
    Parameters:
        password (str): The input password.
    
    Returns:
        bool: True if found in common password list, otherwise False.
    """
    return password in COMMON_PASSWORDS

# Function to visualize password analysis results
def visualize_results(password):
    """
    Generates a visual analysis of a given password, including strength, brute-force time, and dictionary attack check.
    
    Parameters:
        password (str): The input password.
    """
    strength, strength_score = password_strength(password)
    crack_time = brute_force_time(password)
    is_common = dictionary_attack(password)

    # Define Plot Settings
    fig, axes = plt.subplots(1, 3, figsize=(15, 4))
    fig.suptitle(f"Password Analysis for: {password}", fontsize=14, fontweight="bold")

    # Plot 1: Password Strength Visualization
    strength_levels = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
    strength_scores = [1, 2, 3, 4, 5]
    colors = ['red', 'orange', 'yellow', 'green', 'blue']

    axes[0].bar(strength_levels, strength_scores, color=colors, alpha=0.6)
    axes[0].bar(strength, strength_score, color='black')  # Highlight user's score
    axes[0].set_title("Password Strength", fontsize=12, fontweight="bold")
    axes[0].set_ylabel("Strength Score")

    # Plot 2: Brute Force Cracking Time Visualization
    time_labels = ["Seconds", "Minutes", "Hours", "Days", "Years"]
    time_scales = [1, 60, 3600, 86400, 31536000]
    converted_times = [crack_time / scale for scale in time_scales]

    axes[1].bar(time_labels, converted_times, color=colors, alpha=0.6)
    axes[1].set_yscale("log")  # Logarithmic scale for better visualization
    axes[1].set_ylabel("Time to Crack (Log Scale)")
    axes[1].set_title("Brute Force Attack Time", fontsize=12, fontweight="bold")

    # Plot 3: Dictionary Attack Check Visualization
    colors_dict = ['red' if is_common else 'green']
    axes[2].bar(["Common Passwords"], [1 if is_common else 0], color=colors_dict, alpha=0.8)
    axes[2].set_yticks([])
    axes[2].set_title("Dictionary Attack Check", fontsize=12, fontweight="bold")
    axes[2].text(0, 0.5, "⚠️ Found!" if is_common else "✅ Safe", fontsize=15, ha='center', color="white", fontweight="bold")

    # Improve layout
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.show()

    # Print Final Results
    print(f"🔍 Password Strength: {strength}")
    print(f"⏳ Estimated Brute Force Cracking Time: {crack_time:.2e} seconds")
    if is_common:
        print("⚠️ WARNING: This password is found in common leaked password lists! (Very Unsafe)")
    else:
        print("✅ This password is NOT in common leaked password lists.")

# User Input & Run Analysis
password = input("Enter a password to analyze: ")
visualize_results(password)
