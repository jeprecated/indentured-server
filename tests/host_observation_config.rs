use indentured_server::config::Config;

#[test]
fn host_observation_fragment_preserves_identity_and_limits_actions() {
    let base = include_str!("../config/config.toml");
    let original: Config = toml::from_str(base).unwrap();
    let merged = format!(
        "{base}\n{}",
        include_str!("../config/host-observation.toml.example")
    );
    let mut config: Config = toml::from_str(&merged).unwrap();
    // Deployment placeholders are intentionally not installed on this test host.
    // Validate the complete policy using a known executable, without running it.
    let executable = std::env::current_exe().unwrap();
    let task = config.tasks.get_mut("host_observation").unwrap();
    task.executable = Some(executable.clone());
    let session = task.session.as_mut().unwrap();
    session.teardown.executable = Some(executable.clone());
    session.action_dispatcher.as_mut().unwrap().executable = Some(executable);
    config.validate().unwrap();
    assert_eq!(config.build.run_as_user, original.build.run_as_user);
    assert_eq!(config.build.run_as_group, original.build.run_as_group);
    let task = &config.tasks["host_observation"];
    let session = task.session.as_ref().unwrap();
    assert!(session.source_updates.is_none());
    assert!(session.services.is_empty());
    assert!(session.actions.is_empty());
    let dispatcher = session.action_dispatcher.as_ref().unwrap();
    assert!(!dispatcher.allow_unlisted);
    assert_eq!(dispatcher.actions.len(), 2);
    assert!(dispatcher.actions.contains_key("host-list"));
    assert!(dispatcher.actions.contains_key("host-capture"));
    assert!(dispatcher.args.iter().any(|arg| arg == "--peer-uid"));
    assert_eq!(
        dispatcher.artifacts.include,
        [".indentured-output/action/host-*/**"]
    );
}
