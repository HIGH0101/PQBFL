import tenseal as ts
import pickle

# Create HE context with private key
BFV_config_with_key = ts.context(
    ts.SCHEME_TYPE.BFV,
    poly_modulus_degree=8192,
    plain_modulus=1032193
)
BFV_config_with_key.generate_galois_keys()
BFV_config_with_key.generate_relin_keys()

# Serialize the context with the private key
serialized_with_key = BFV_config_with_key.serialize(save_secret_key=True)
serialized_without_key = BFV_config_with_key.serialize(save_secret_key=False)

# Save to a separate file without the private key
with open("C:\\Users\\tester\\Desktop\\PQBFL\\server\\keys\\BFV_without_priv_key.pkl", "wb") as f:
    pickle.dump(serialized_without_key, f)

# Save to a file with the private key
with open("C:\\Users\\tester\\Desktop\\PQBFL\\participant\\keys\\BFV_with_priv_key.pkl", "wb") as f:
    pickle.dump(serialized_with_key, f)




# Create HE context with private key using CKKS scheme
CKKS_config_with_key = ts.context(
    ts.SCHEME_TYPE.CKKS,                   # Set the scheme to CKKS
    poly_modulus_degree=8192,               # Typical polynomial modulus degree for CKKS
    coeff_mod_bit_sizes=[40, 21, 21, 40]    # Example of coefficient modulus sizes (adjust if needed)
)
CKKS_config_with_key.global_scale = 2**21     # Set the global scale (you may adjust depending on your needs)
CKKS_config_with_key.generate_galois_keys()
CKKS_config_with_key.generate_relin_keys()

# Serialize the context with the private key
serialized_with_key = CKKS_config_with_key.serialize(save_secret_key=True)
serialized_without_key = CKKS_config_with_key.serialize(save_secret_key=False)

# Save to a separate file without the private key
with open("C:\\Users\\tester\\Desktop\\PQBFL\\server\\keys\\CKKS_without_priv_key.pkl", "wb") as f:
    pickle.dump(serialized_without_key, f)

# Save to a file with the private key
with open("C:\\Users\\tester\\Desktop\\PQBFL\\participant\\keys\\CKKS_with_priv_key.pkl", "wb") as f:
    pickle.dump(serialized_with_key, f)
