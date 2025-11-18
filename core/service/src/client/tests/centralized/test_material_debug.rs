//! Debug test for material manager

use crate::util::key_setup::test_material_manager::TestMaterialManager;
use crate::util::key_setup::test_material_spec::TestMaterialSpec;
use anyhow::Result;

#[tokio::test]
async fn test_material_manager_debug() -> Result<()> {
    // Enable debug logging
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    let source_path = std::env::current_dir()?.parent().unwrap().parent().unwrap().join("test-material");
    println!("🔍 Source path: {}", source_path.display());
    println!("🔍 Source exists: {}", source_path.exists());
    
    if source_path.exists() {
        println!("📁 Source directory contents:");
        for entry in std::fs::read_dir(&source_path)? {
            let entry = entry?;
            println!("  - {}", entry.file_name().to_string_lossy());
        }
    }
    
    let manager = TestMaterialManager::new(Some(source_path));
    let spec = TestMaterialSpec::centralized_basic();
    
    println!("🔍 Spec requires signing keys: {}", spec.requires_key_type(crate::util::key_setup::test_material_spec::KeyType::SigningKeys));
    
    let material_dir = manager.setup_test_material(&spec, "debug_test").await?;
    
    println!("🔍 Temp directory: {}", material_dir.path().display());
    
    // Check what was copied
    let priv_dir = material_dir.path().join("PRIV");
    if priv_dir.exists() {
        println!("📁 PRIV directory contents:");
        for entry in std::fs::read_dir(&priv_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            println!("  - {}", name);
            
            if name == "SigningKey" {
                println!("📁 SigningKey directory contents:");
                for signing_entry in std::fs::read_dir(entry.path())? {
                    let signing_entry = signing_entry?;
                    println!("    - {}", signing_entry.file_name().to_string_lossy());
                }
            }
        }
    } else {
        println!("❌ PRIV directory does not exist!");
    }
    
    Ok(())
}
