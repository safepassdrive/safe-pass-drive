import random
import string

def generate_otp(length=6):
    """Generate a random OTP of specified length."""
    digits = string.digits
    otp = ''.join(random.choice(digits) for _ in range(length))
    return otp

def send_otp(contact, otp):
    """Simulate sending an OTP to the provided contact."""
    # This function simulates sending an OTP.
    # In a real-world application, you would integrate with an SMS gateway or email_services service.
    print(f"Sending OTP {otp} to {contact}")

# Example usage
if __name__ == '__main__':
    contact = '1234567890'
    otp = generate_otp()
    send_otp(contact, otp)
    print(f"Generated OTP: {otp}")
