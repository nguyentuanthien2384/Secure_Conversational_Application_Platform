//! A bounded, stateless stdin/stdout bridge to OpenMLS. No keys are written to
//! disk or logs; the caller encrypts returned state before acknowledging it.
use std::{collections::HashMap, io::{self, Read}};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};

const MAX_INPUT: u64 = 8 * 1024 * 1024;
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
type Result<T> = std::result::Result<T, ()>;
fn enc(v: impl AsRef<[u8]>) -> String { URL_SAFE_NO_PAD.encode(v) }
fn txt<'a>(v: &'a Value, key: &str) -> Result<&'a str> { v[key].as_str().ok_or(()) }
fn bytes(v: &Value, key: &str) -> Result<Vec<u8>> { URL_SAFE_NO_PAD.decode(txt(v, key)?).map_err(|_| ()) }
fn wire(message: MlsMessageOut) -> Result<String> { message.to_bytes().map(enc).map_err(|_| ()) }
fn package(provider: &OpenMlsRustCrypto, raw: Vec<u8>) -> Result<KeyPackage> {
    KeyPackageIn::tls_deserialize_exact(raw).map_err(|_| ())?
        .validate(provider.crypto(), ProtocolVersion::Mls10).map_err(|_| ())
}
fn roster(group: &MlsGroup) -> Vec<Value> {
    group.members().map(|m| json!({"device_id": String::from_utf8_lossy(m.credential.serialized_content()),
        "signing_key":enc(&m.signature_key)})).collect()
}
fn execute(input: Value) -> Result<Value> {
    let provider = OpenMlsRustCrypto::default();
    let op = txt(&input, "op")?;
    if op == "inspect" {
        let kp = package(&provider, bytes(&input, "key_package")?)?;
        return Ok(json!({"device_id":String::from_utf8_lossy(kp.leaf_node().credential().serialized_content()),
            "signing_key":enc(kp.leaf_node().signature_key().as_slice())}));
    }
    let identity = txt(&input, "device_id")?;
    if identity.len() != 36 { return Err(()); }
    let previous = &input["state"];
    let signer = if previous.is_null() {
        SignatureKeyPair::new(SUITE.signature_algorithm()).map_err(|_| ())?
    } else {
        let values: Vec<(Vec<u8>, Vec<u8>)> = serde_json::from_value(previous["storage"].clone()).map_err(|_| ())?;
        if values.len() > 10000 { return Err(()); }
        *provider.storage().values.write().map_err(|_| ())? = values.into_iter().collect::<HashMap<_,_>>();
        serde_json::from_value(previous["signer"].clone()).map_err(|_| ())?
    };
    let credential = CredentialWithKey { credential: BasicCredential::new(identity.as_bytes().to_vec()).into(),
        signature_key:signer.to_public_vec().into() };
    let mut output = json!({"signing_key":enc(signer.public())});
    if op == "key_package" {
        let kp = KeyPackage::builder().build(SUITE, &provider, &signer, credential).map_err(|_| ())?;
        output["key_package"] = json!(enc(kp.key_package().tls_serialize_detached().map_err(|_| ())?));
    } else {
        let group_id = GroupId::from_slice(txt(&input, "group_id")?.as_bytes());
        let mut group = if op == "create" {
            if MlsGroup::load(provider.storage(), &group_id).map_err(|_| ())?.is_some() { return Err(()); }
            let config = MlsGroupCreateConfig::builder().ciphersuite(SUITE)
                .use_ratchet_tree_extension(true).build();
            MlsGroup::new_with_group_id(&provider, &signer, &config, group_id.clone(), credential).map_err(|_| ())?
        } else if op == "join" {
            if MlsGroup::load(provider.storage(), &group_id).map_err(|_| ())?.is_some() { return Err(()); }
            let welcome = MlsMessageIn::tls_deserialize_exact(bytes(&input, "message")?).map_err(|_| ())?
                .into_welcome().ok_or(())?;
            let config = MlsGroupJoinConfig::builder().use_ratchet_tree_extension(true).build();
            let joined = StagedWelcome::new_from_welcome(&provider, &config, welcome, None).map_err(|_| ())?
                .into_group(&provider).map_err(|_| ())?;
            if joined.group_id() != &group_id { return Err(()); }
            joined
        } else {
            MlsGroup::load(provider.storage(), &group_id).map_err(|_| ())?.ok_or(())?
        };
        match op {
            "create" | "join" | "status" => {},
            "add" => {
                let kp = package(&provider, bytes(&input, "key_package")?)?;
                let (commit, welcome, _) = group.add_members(&provider, &signer, &[kp]).map_err(|_| ())?;
                output["commit"] = json!(wire(commit)?);
                output["welcome"] = json!(wire(welcome.into())?);
                group.merge_pending_commit(&provider).map_err(|_| ())?;
            },
            "remove" => {
                let target = txt(&input, "target_device")?;
                let index = group.members().find(|m| m.credential.serialized_content() == target.as_bytes()).ok_or(())?.index;
                let (commit, _, _) = group.remove_members(&provider, &signer, &[index]).map_err(|_| ())?;
                output["commit"] = json!(wire(commit)?);
                group.merge_pending_commit(&provider).map_err(|_| ())?;
            },
            "send" => {
                let text = bytes(&input, "plaintext")?;
                if text.len() > 32768 { return Err(()); }
                group.set_aad(bytes(&input, "aad")?);
                output["message"] = json!(wire(group.create_message(&provider, &signer, &text).map_err(|_| ())?)?);
            },
            "receive" => {
                let msg = MlsMessageIn::tls_deserialize_exact(bytes(&input, "message")?).map_err(|_| ())?
                    .try_into_protocol_message().map_err(|_| ())?;
                let processed = group.process_message(&provider, msg).map_err(|_| ())?;
                output["sender_device"] = json!(String::from_utf8_lossy(processed.credential().serialized_content()));
                output["aad"] = json!(enc(processed.aad()));
                match processed.into_content() {
                    ProcessedMessageContent::ApplicationMessage(message) => {
                        output["kind"] = json!("application");
                        output["plaintext"] = json!(enc(message.into_bytes()));
                    },
                    ProcessedMessageContent::StagedCommitMessage(commit) => {
                        output["kind"] = json!("commit");
                        group.merge_staged_commit(&provider, *commit).map_err(|_| ())?;
                    },
                    _ => return Err(()),
                }
            },
            _ => return Err(()),
        }
        output["epoch"] = json!(group.epoch().as_u64());
        output["members"] = json!(roster(&group));
        output["active"] = json!(group.is_active());
    }
    let storage:Vec<(Vec<u8>,Vec<u8>)> = provider.storage().values.read().map_err(|_| ())?
        .iter().map(|(k,v)|(k.clone(),v.clone())).collect();
    output["state"] = json!({"signer":serde_json::to_value(signer).map_err(|_| ())?,"storage":storage});
    Ok(output)
}
fn main() {
    let mut raw = Vec::new();
    let result = io::stdin().take(MAX_INPUT+1).read_to_end(&mut raw).map_err(|_| ())
        .and_then(|_| if raw.len() as u64 > MAX_INPUT { Err(()) } else { Ok(()) })
        .and_then(|_| serde_json::from_slice(&raw).map_err(|_| ()))
        .and_then(execute);
    match result {
        Ok(output) => println!("{}", output),
        Err(_) => { eprintln!("MLS operation rejected; state was not committed."); std::process::exit(2); },
    }
}
