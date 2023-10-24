use enigma_api::Permission;
use enigma_api::User;
use rusqlite::params;

use crate::Error;
use crate::Result;

use super::Database;
use super::Tx;

impl Database {
    pub(crate) fn create_user_with_hash_password(
        &mut self,
        username: &str,
        password_hash: &str,
    ) -> Result<i64> {
        let mut tx = self.transaction()?;

        let result = {
            tracing::trace!("[database] create_user_with_hash_password:");
            tracing::trace!("  username: {:?}", username);
            tracing::trace!("  password_hash: {:?}", password_hash);

            let mut stmt = tx
                .inner()
                .prepare("INSERT INTO users (username, password_hash) VALUES (?1, ?2)")?;
            let result = stmt.insert(params![username, password_hash])?;
            tracing::trace!("  => {:?}", result);
            result
        };

        tx.commit()?;
        Ok(result)
    }

    pub fn create_user(&mut self, username: &str, password: &str) -> Result<i64> {
        let password_hash = self.hash_password(password)?;
        self.create_user_with_hash_password(username, &password_hash)
    }

    pub fn add_permission(&mut self, user_id: i64, site: &str, permission: &str) -> Result<()> {
        let mut tx = self.transaction()?;

        {
            tracing::trace!("[database] add_permission:");
            tracing::trace!("  user_id: {:?}", user_id);
            tracing::trace!("  site: {:?}", site);
            tracing::trace!("  permission: {:?}", permission);

            let mut stmt = tx.inner().prepare(
                "INSERT INTO permissions (user_id, site, permission) VALUES (?1, ?2, ?3)",
            )?;
            stmt.insert(params![user_id, site, permission])?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn remove_permission(&mut self, user_id: i64, site: &str, permission: &str) -> Result<()> {
        let mut tx = self.transaction()?;

        {
            tracing::trace!("[database] remove_permission:");
            tracing::trace!("  user_id: {:?}", user_id);
            tracing::trace!("  site: {:?}", site);
            tracing::trace!("  permission: {:?}", permission);

            let mut stmt = tx.inner().prepare(
                "DELETE FROM permissions WHERE user_id = ?1 AND site = ?2 AND permission = ?3",
            )?;
            stmt.execute(params![user_id, site, permission])?;
        }

        tx.commit()?;
        Ok(())
    }

    pub(crate) fn tx_get_user_permissions(tx: &Tx, user_id: i64) -> Result<Vec<Permission>> {
        let mut stmt = tx
            .inner()
            .prepare("SELECT * FROM permissions WHERE user_id = ?1")?;
        let mut rows = stmt.query(params![user_id])?;

        let mut permissions = vec![];
        while let Some(row) = rows.next()? {
            permissions.push(Permission {
                site: row.get("site")?,
                permission: row.get("permission")?,
            });
        }

        Ok(permissions)
    }

    pub(crate) fn tx_get_user_password(tx: &Tx, username: &str) -> Result<(i64, String)> {
        let mut stmt = tx
            .inner()
            .prepare("SELECT * FROM users WHERE username = ?1")?;
        let mut rows = stmt.query(params![username])?;

        let row = rows.next()?.ok_or(Error::UserNotFound)?;
        let user_id = row.get("id")?;
        let password_hash = row.get("password_hash")?;
        Ok((user_id, password_hash))
    }

    pub(crate) fn tx_get_user_by_id(tx: &Tx, user_id: i64) -> Result<User> {
        let mut stmt = tx.inner().prepare("SELECT * FROM users WHERE id = ?1")?;
        let mut rows = stmt.query(params![user_id])?;

        let row = rows.next()?.ok_or(Error::UserNotFound)?;
        let mut user = User {
            id: row.get("id")?,
            username: row.get("username")?,
            permissions: vec![],
        };

        user.permissions = Self::tx_get_user_permissions(tx, user.id)?;
        Ok(user)
    }

    pub fn get_user_by_id(&mut self, user_id: i64) -> Result<User> {
        let mut tx = self.transaction()?;
        let user = {
            tracing::trace!("[database] get_user_by_id:");
            tracing::trace!("  user_id: {:?}", user_id);
            Self::tx_get_user_by_id(&tx, user_id)?
        };

        tx.commit()?;
        Ok(user)
    }

    pub fn get_user_by_username(&mut self, username: &str) -> Result<User> {
        let mut tx = self.transaction()?;
        let user = {
            tracing::trace!("[database] get_user_by_username:");
            tracing::trace!("  username: {:?}", username);

            let mut stmt = tx
                .inner()
                .prepare("SELECT * FROM users WHERE username = ?1")?;
            let mut rows = stmt.query(params![username])?;

            let row = rows.next()?.ok_or(Error::UserNotFound)?;
            let mut user = User {
                id: row.get("id")?,
                username: row.get("username")?,
                permissions: vec![],
            };

            user.permissions = Self::tx_get_user_permissions(&tx, user.id)?;
            user
        };

        tx.commit()?;
        Ok(user)
    }

    pub fn list_users(&mut self) -> Result<Vec<User>> {
        let mut users = vec![];
        let mut tx = self.transaction()?;

        {
            let mut stmt = tx.inner().prepare("SELECT * FROM users")?;
            let mut rows = stmt.query(params![])?;

            while let Some(row) = rows.next()? {
                let mut user = User {
                    id: row.get("id")?,
                    username: row.get("username")?,
                    permissions: vec![],
                };

                user.permissions = Self::tx_get_user_permissions(&tx, user.id)?;
                users.push(user);
            }
        }

        tx.commit()?;
        Ok(users)
    }

    pub fn delete_user_by_username(&mut self, username: &str) -> Result<()> {
        let mut tx = self.transaction()?;

        {
            tracing::trace!("[database] delete_user_by_username:");
            tracing::trace!("  username: {:?}", username);

            let mut stmt = tx
                .inner()
                .prepare("DELETE FROM users WHERE username = ?1")?;
            stmt.execute(params![username])?;
        }

        tx.commit()?;
        Ok(())
    }
}
