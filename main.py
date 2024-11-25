from pathlib import Path
from syftbox.lib import Client
import os
import json
from datetime import datetime, UTC
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.backends import default_backend
import base64
import shutil

API_NAME = "e_voting"

def generate_key_pair(client):
    secret_key_path = client.config.data_dir / "private" / API_NAME
    secret_key_path.mkdir(parents=True, exist_ok=True)
    secret_key_file = secret_key_path / "private_key.pem"

    public_key_path = client.datasite_path / "public" / API_NAME
    public_key_path.mkdir(parents=True, exist_ok=True)
    public_key_file = public_key_path / "public.json"
    # Check if both private and public key files exist
    if secret_key_file.exists() and public_key_file.exists():
        with open(secret_key_file, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        with open(public_key_file, 'r') as f:
            public_key_json = json.load(f)
            pem_public = public_key_json["publicKey"].encode('utf-8')
            public_key = serialization.load_pem_public_key(
                pem_public,
                backend=default_backend()
            )
        return private_key, public_key
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Get public key
    public_key = private_key.public_key()

    # Serialize private key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save private key to file
    with open(secret_key_file, 'wb') as f:
        f.write(pem_private)

    # Create and save public.json
    public_key_str = pem_public.decode('utf-8')
    public_key_json = {
        "publicKey": public_key_str
    }
    
    with open(public_key_file, 'w') as f:
        json.dump(public_key_json, f, indent=2)
        
    return private_key, public_key

def decrypt_vote(private_key: RSAPrivateKey, encrypted_vote: str) -> int:
    """
    Decrypt an encrypted vote using RSA private key.
    
    Args:
        private_key: RSA private key object
        encrypted_vote: Base64 encoded encrypted vote string
    
    Returns:
        int: Decrypted vote (0 for cat, 1 for dog)
    """
    try:
        # Decode base64 encrypted vote
        encrypted_data = base64.b64decode(encrypted_vote)
        
        # Decrypt the vote
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Convert decrypted bytes to integer
        vote = int(decrypted_data.decode('utf-8'))
        
        # Validate vote value
        if vote not in [0, 1]:
            raise ValueError("Invalid vote value")
            
        return vote
        
    except ValueError as e:
        raise ValueError(f"Invalid vote format: {str(e)}")
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")


def count_votes(datasites_path: Path, peers: list[str], private_key) -> tuple[int, int]:
    """
    Counts votes from all peers.
    Returns tuple of (cat_votes, dog_votes).
    """
    cat_votes = 0
    dog_votes = 0
    
    for peer in peers:
        vote_file = datasites_path / peer / "public" / "Vote.txt"
        
        if not vote_file.exists():
            continue
            
        try:
            with open(vote_file, "r") as f:
                encrypted_vote = f.read().strip()
                vote = decrypt_vote(private_key, encrypted_vote)
                if vote == 0:
                    cat_votes += 1
                elif vote == 1:
                    dog_votes += 1
        except Exception as e:
            print(f"Error processing vote from {peer}: {e}")
            continue
    
    return cat_votes, dog_votes

def update_totals(output_file: Path, cat_votes: int, dog_votes: int):
    """
    Updates the total.json file with current vote counts and timestamp.
    """
    current_time = datetime.now(UTC)
    data = {
        "cats": cat_votes,
        "dogs": dog_votes,
        "timestamp": current_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    
    with open(output_file, "w") as f:
        json.dump(data, f, indent=4)

def should_run() -> bool:
    INTERVAL = 1
    timestamp_file = f"./script_timestamps/{API_NAME}_last_run"
    os.makedirs(os.path.dirname(timestamp_file), exist_ok=True)
    now = datetime.now().timestamp()
    time_diff = INTERVAL
    if os.path.exists(timestamp_file):
        try:
            with open(timestamp_file, "r") as f:
                last_run = int(f.read().strip())
                time_diff = now - last_run
        except (FileNotFoundError, ValueError):
            print(f"Unable to read timestamp file: {timestamp_file}")
    if time_diff >= INTERVAL:
        with open(timestamp_file, "w") as f:
            f.write(f"{int(now)}")
        return True
    return False

def copy_html_files(source: Path, destination: Path):
    """
    Copies all files from source directory to destination directory.
    """
    if not source.is_dir():
        raise ValueError(f"Source {source} is not a directory.")
    if not destination.exists():
        destination.mkdir(parents=True)
    elif not destination.is_dir():
        raise ValueError(f"Destination {destination} is not a directory.")

    for item in source.iterdir():
        if item.is_file():
            shutil.copy2(item, destination / item.name)

if __name__ == "__main__":
    if not should_run():
        print(f"Skipping {API_NAME}, not enough time has passed.")
        exit(0)
        
    client = Client.load()
    
    # Copy HTML and other assets
    assets_path = Path("./assets")
    copy_html_files(assets_path, client.datasite_path / "public" / API_NAME )
    
    # Setup or load key
    private_key, _ = generate_key_pair(client)
    
    # Get list of peers
    peers = [d.name for d in client.datasite_path.parent.iterdir() if d.is_dir()]
    
    # Count votes
    cat_votes, dog_votes = count_votes(client.datasite_path.parent, peers, private_key)
    
    # Update totals.json
    output_file = client.datasite_path / "public" / API_NAME / "total.json"
    update_totals(output_file, cat_votes, dog_votes)