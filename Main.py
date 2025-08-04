from flask import Flask, send_from_directory, jsonify, request
from flask_cors import CORS
import secrets
import string
import base64
import hashlib
from dataclasses import dataclass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

@dataclass
class PasswordSettings:
    length: int = 100
    use_symbols: bool = True
    avoid_ambiguous: bool = True
    kdf_iterations: int = 300_000

class PasswordGenerator:
    def __init__(self, settings: PasswordSettings):
        self.settings = settings
        self.charset = self._build_charset()

    def _build_charset(self) -> str:
        chars = string.ascii_letters + string.digits
        if self.settings.use_symbols:
            chars += "!@#$%^&*()_+=<>?/|{}[]~"
        if self.settings.avoid_ambiguous:
            chars = ''.join(c for c in chars if c not in "l1I0O")
        return chars  # Solo caracteres ASCII seguros

    def generate(self) -> str:
        return ''.join(secrets.choice(self.charset) for _ in range(self.settings.length))

def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/generar', methods=['GET'])
def generar_contraseñas():
    try:
        length = int(request.args.get('length', 100))
        if length < 16 or length > 512:
            return jsonify({"error": "La longitud debe estar entre 16 y 512 caracteres."}), 400

        amount = int(request.args.get('amount', 1))
        if amount < 1 or amount > 20:
            return jsonify({"error": "Solo se pueden generar entre 1 y 20 contraseñas a la vez."}), 400

    except ValueError:
        return jsonify({"error": "Parámetros inválidos."}), 400

    settings = PasswordSettings(length=length)
    resultados = []

    for _ in range(amount):
        generator = PasswordGenerator(settings)
        password = generator.generate()
        hashed = hashlib.sha256(password.encode()).digest()

        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(12)
        key = derive_key(password, salt, settings.kdf_iterations)

        aesgcm = AESGCM(key)
        encrypted = aesgcm.encrypt(iv, hashed, None)

        resultado = {
            "original": password,
            "encrypted": base64.b64encode(encrypted).decode(),
            "iv": base64.b64encode(iv).decode(),
            "salt": base64.b64encode(salt).decode(),
            "version": "1.0"
        }

        resultados.append(resultado)

    return jsonify(resultados)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
