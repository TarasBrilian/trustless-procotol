use security_framework::passwords::{set_generic_password, get_generic_password, delete_generic_password};
use anyhow::{Result, Context};

const SERVICE_NAME: &str = "zk-wallet";
const ACCOUNT_NAME: &str = "ethereum-private-key";

pub fn store_private_key(private_key: &[u8]) -> Result<()> {
    set_generic_password(SERVICE_NAME, ACCOUNT_NAME, private_key)
        .context("Failed to store private key in Keychain")?;
    Ok(())
}

pub fn retrieve_private_key() -> Result<Vec<u8>> {
    let key = get_generic_password(SERVICE_NAME, ACCOUNT_NAME)
        .context("Failed to retrieve private key from Keychain")?;
    Ok(key.to_vec())
}

pub fn delete_private_key() -> Result<()> {
    delete_generic_password(SERVICE_NAME, ACCOUNT_NAME)
        .context("Failed to delete private key from Keychain")?;
    Ok(())
}
