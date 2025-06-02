from werkzeug.security import generate_password_hash
hash = generate_password_hash("raak", method="pbkdf2:sha256")

print(hash)
