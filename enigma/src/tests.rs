use enigma_api::TrackInformation;

use crate::VerifySession;

use super::Database;

// Setup and teardown functions for tests
fn setup_test_db() -> Database {
    let db =
        Database::new(":memory:", "vkzROAFwR3Zgx+KZU7Ecxw").expect("failed to create database");
    db.init().expect("failed to initialize database");
    db
}

#[test]
#[tracing_test::traced_test]
fn test_create_user_with_hash_password() {
    let mut db = setup_test_db();
    let username = "testuser";
    let password_hash = "hashed_password";
    let result = db
        .create_user_with_hash_password(username, password_hash)
        .expect("failed to create user");
    assert!(result > 0);
}

#[test]
#[tracing_test::traced_test]
fn test_create_user() {
    let mut db = setup_test_db();
    let username = "testuser";
    let password = "password123";
    let result = db
        .create_user(username, password)
        .expect("failed to create user");
    assert!(result > 0);
}

#[test]
#[tracing_test::traced_test]
fn test_add_and_remove_permission() {
    let mut db = setup_test_db();

    let user_id = db.create_user("test", "test").unwrap();
    let site = "example.com";
    let permission = "read";

    db.add_permission(user_id, site, permission).unwrap();

    let permissions = db.get_user_by_id(user_id).unwrap().permissions;
    assert_eq!(permissions.len(), 1);
    assert_eq!(permissions[0].site, site);
    assert_eq!(permissions[0].permission, permission);

    db.remove_permission(user_id, site, permission).unwrap();
    let permissions = db.get_user_by_id(user_id).unwrap().permissions;
    assert!(permissions.is_empty());
}

#[test]
fn test_create_session_token() {
    let mut db = setup_test_db();
    let _ = db.create_user_with_hash_password("test", "$pbkdf2-sha256$i=600000,l=32$vkzROAFwR3Zgx+KZU7Ecxw$npnw9yAJfs39y2cuHGwgCyklCz5yaUy8pt+LhNe7zak")
        .expect("failed to create user");

    let track = TrackInformation {
        device: Some("Android".into()),
        user_agent: Some("Safari".into()),
        ip_address: Some("192.168.1.1".into()),
        location: Some("USA".into()),
        os: Some("iOS".into()),
        browser: Some("Safari".into()),
        screen_resolution: Some("1125x2436".into()),
        timezone: Some("UTC-5".into()),
    };
    let session = db
        .create_session("test", "password123", track)
        .expect("failed to create session");
    assert_eq!(session.user.username, "test");
    assert_eq!(session.track.device.as_ref().unwrap(), "Android");

    let get_session = db
        .verify_session(&session.session_token)
        .expect("failed to get session");
    assert_eq!(matches!(get_session, VerifySession::Session(_)), true);
    assert_eq!(session, get_session.unwrap_session());
}
