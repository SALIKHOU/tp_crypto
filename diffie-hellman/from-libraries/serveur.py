from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import flask

app = flask.Flask(__name__)

client_shared_keys = {}

# Génération des paramètres DH (g=2, key_size=2048)
# Il est recommandé d'utiliser les spécifications fournies par des organismes reconnus comme le NIST
parameters = dh.generate_parameters(generator=2, key_size=2048)

# Génération de la clé privée du serveur
private_key_server = parameters.generate_private_key()

# Calcul de la clé publique du serveur
public_key = private_key_server.public_key()

# Fonction pour calculer la clé partagée
def calculate_shared_key(client_public_key_pem):
    client_public_key = serialization.load_pem_public_key(client_public_key_pem)
    shared_key = private_key_server.exchange(client_public_key)
    return shared_key

@app.route('/key_exchange', methods=['POST'])
def key_exchange():
    data = flask.request.json
    
    if 'public_key' in data:
        client_public_key_pem = data['public_key'].encode('utf-8')
        
        # Calcul de la clé partagée avec la clé publique du client
        shared_key = calculate_shared_key(client_public_key_pem)

        # Enregistrer la clé partagée avec le client
        client_shared_keys[flask.request.remote_addr] = shared_key

        # Sérialiser la clé publique du serveur en PEM
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Retourner la clé publique du serveur au client
        return flask.jsonify({'public_key': public_key_pem})
    else:
        return flask.jsonify({'error': 'Client public key not found'})

if __name__ == '__main__':
    app.run(debug=True)
