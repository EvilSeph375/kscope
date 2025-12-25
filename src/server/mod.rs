pub mod session;

use crate::protocol::ServerConfig;
use crate::Result;

pub struct KScopeServer {
    config: ServerConfig,
}

impl KScopeServer {
    pub async fn new(config: ServerConfig) -> Result<Self> {
        Ok(Self { config })
    }
    
    pub async fn run(&mut self) -> Result<()> {
        println!("KScope server starting with config: {:?}", self.config);
        // TODO: Implement server logic
        Ok(())
    }
}
