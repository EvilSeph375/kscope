use crate::KScopeError;

pub fn add_default_route(_interface: &str, _via: Option<&str>) -> Result<(), KScopeError> {
    println!("[MOCK] Would add default route via {}", _interface);
    Ok(())
}

pub fn add_route(_interface: &str, _destination: &str, _via: Option<&str>) -> Result<(), KScopeError> {
    println!("[MOCK] Would add route {} via {}", _destination, _interface);
    Ok(())
}
