use indentured_server::config::Config;

#[test]
fn host_feature_is_default_off_and_independent_of_tasks() {
    let original: Config = toml::from_str(include_str!("../config/config.toml")).unwrap();
    assert!(!original.host_observation.enabled);
    let mut value: toml::Value = toml::from_str(include_str!("../config/config.toml")).unwrap();
    let feature: toml::Value =
        toml::from_str(include_str!("../config/host-observation.toml.example")).unwrap();
    value["host_observation"] = feature["host_observation"].clone();
    let mut config: Config = value.try_into().unwrap();
    config.validate().unwrap();
    assert!(config.host_observation.enabled);
    assert_eq!(config.build.run_as_user, original.build.run_as_user);
    assert_eq!(config.build.run_as_group, original.build.run_as_group);
    assert_eq!(config.tasks.len(), original.tasks.len());
    assert!(!config.tasks.contains_key("host_observation"));
    config.tasks.clear();
    config.validate().unwrap();
    config.host_observation.enabled = false;
    config.validate().unwrap();
}

#[test]
fn invalid_host_policy_fails_closed() {
    let original: Config = toml::from_str(include_str!("../config/config.toml")).unwrap();
    for mutation in 0..5 {
        let mut config = original.clone();
        config.host_observation.enabled = true;
        config.host_observation.socket = Some("/private/host/control.sock".into());
        config.host_observation.peer_uid = Some(501);
        match mutation {
            0 => config.host_observation.socket = None,
            1 => config.host_observation.peer_uid = None,
            2 => config.host_observation.socket = Some("relative.sock".into()),
            3 => config.host_observation.socket = Some("/private/../control.sock".into()),
            _ => config.service.http.auth.required = false,
        }
        assert!(config.validate().is_err());
    }
    let invalid = "[host_observation]\nenabled = false\ncommand = 'sh'\n";
    assert!(toml::from_str::<Config>(&format!("schema_version = '12'\n{invalid}")).is_err());
    let omitted: Config = toml::from_str("schema_version = '12'\n").unwrap();
    assert!(!omitted.host_observation.enabled);
    assert!(omitted.tasks.is_empty());
}
