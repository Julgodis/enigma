use kodama_api::query;
use kodama_api::query::param;
use kodama_api::query::IntoQuery;
use kodama_api::query::Query;
use kodama_api::DatabaseQuery;
use kodama_api::FromRow;
use kodama_api::Transaction;
use pbkdf2::password_hash::SaltString;
use rand_core::OsRng;
use rusqlite::params;

use crate::Permission;
use crate::Result;
use crate::Session;
use crate::User;

use super::Database;

pub struct CreateUser {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
}

impl Database {
    pub(crate) fn create_user_with_hash_password(
        &mut self,
        username: &str,
        email: &Option<String>,
        password_hash: &str,
        password_salt: SaltString,
        password_method: &str,
    ) -> Result<i64> {
        let tx = self.database.transaction()?;
        let salt = password_salt.as_str();

        let result = {
            tracing::trace!("[database] create_user_with_hash_password:");
            tracing::trace!("  username: {:?}", username);
            tracing::trace!("  password_hash: {:?}", password_hash);

            let query = Query::insert_into("users")
                .column("username", param(1))
                .column("password_hash", param(2))
                .column("password_salt", param(3))
                .column("password_method", param(4))
                .column("email", param(5))
                .into_query();

            let result = query.insert(
                &self.database,
                params![username, password_hash, salt, password_method, email],
            )?;
            tracing::trace!("  => {:?}", result);
            result
        };

        tx.commit()?;
        Ok(result)
    }

    pub fn create_user(&mut self, user: CreateUser) -> Result<i64> {
        let password_salt = SaltString::generate(&mut OsRng);
        let password_hash = self.hash_password(&password_salt, &user.password)?;
        self.create_user_with_hash_password(
            &user.username,
            &user.email,
            &password_hash,
            password_salt,
            "pbkdf2-sha256",
        )
    }

    pub fn add_permission(&mut self, user_id: i64, site: &str, permission: &str) -> Result<()> {
        let tx = self.database.transaction()?;

        {
            tracing::trace!("[database] add_permission:");
            tracing::trace!("  user_id: {:?}", user_id);
            tracing::trace!("  site: {:?}", site);
            tracing::trace!("  permission: {:?}", permission);

            let query = Query::insert_into("permissions")
                .or_ignore()
                .column("user_id", param(1))
                .column("site", param(2))
                .column("permission", param(3))
                .into_query();
            match query.insert(&tx, params![user_id, site, permission]) {
                Ok(_) => (),
                Err(err) => Err(err)?,
            }
        }

        tx.commit()?;
        Ok(())
    }

    pub fn remove_permission(&mut self, user_id: i64, site: &str, permission: &str) -> Result<()> {
        let tx = self.database.transaction()?;

        {
            tracing::trace!("[database] remove_permission:");
            tracing::trace!("  user_id: {:?}", user_id);
            tracing::trace!("  site: {:?}", site);
            tracing::trace!("  permission: {:?}", permission);

            let query = Query::delete_from("permissions")
                .condition(query::eq(query::column("user_id"), param(1)))
                .condition(query::eq(query::column("site"), param(2)))
                .condition(query::eq(query::column("permission"), param(3)))
                .into_query();

            query.delete(&tx, params![user_id, site, permission])?;
        }

        tx.commit()?;
        Ok(())
    }

    pub(crate) fn tx_get_user_permissions(
        tx: &Transaction<'_>,
        user_id: i64,
    ) -> Result<Vec<Permission>> {
        let query = Query::select_from("permissions")
            .column("site")
            .column("permission")
            .condition(query::eq(query::column("user_id"), param(1)))
            .into_query();

        struct InnerPermission {
            site: String,
            permission: String,
        }

        impl FromRow for InnerPermission {
            fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
                Ok(Self {
                    site: row.get("site")?,
                    permission: row.get("permission")?,
                })
            }
        }

        let permissions = query.select_many::<InnerPermission>(tx, params![user_id])?;
        let permissions = permissions
            .into_iter()
            .map(|p| Permission {
                site: p.site,
                permission: p.permission,
            })
            .collect();
        Ok(permissions)
    }

    pub(crate) fn tx_get_user_password(
        tx: &Transaction<'_>,
        username: &str,
    ) -> Result<(i64, String, SaltString, String)> {
        #[derive(Debug)]
        struct InnerUser {
            id: i64,
            password_hash: String,
            password_salt: String,
            password_method: String,
        }

        impl FromRow for InnerUser {
            fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
                Ok(Self {
                    id: row.get("id")?,
                    password_hash: row.get("password_hash")?,
                    password_salt: row.get("password_salt")?,
                    password_method: row.get("password_method")?,
                })
            }
        }

        tracing::trace!("[database] tx_get_user_password:");
        tracing::trace!("  username: {:?}", username);

        let query = Query::select_from("users")
            .all_columns()
            .condition(query::eq(query::column("username"), param(1)))
            .into_query();

        let user = query.select_maybe::<InnerUser>(tx, params![username])?;
        let user = user.ok_or(crate::Error::UserNotFound)?;

        Ok((
            user.id,
            user.password_hash,
            SaltString::from_b64(&user.password_salt)
                .map_err(|_| crate::Error::InvalidPasswordSalt)?,
            user.password_method,
        ))
    }

    pub(crate) fn tx_verify_password(
        tx: &Transaction<'_>,
        username: &str,
        password: &str,
    ) -> Result<Option<i64>> {
        tracing::trace!("[database] tx_verify_password:");
        tracing::trace!("  username: {:?}", username);
        tracing::trace!("  password: [REDACTED]");

        let x = Self::tx_get_user_password(tx, username);
        if let Err(x) = &x {
            tracing::error!("  => {:?}", x);
        }
        let (user_id, password_hash, password_salt, password_method) = match x {
            Ok(user) => user,
            Err(crate::Error::UserNotFound) => return Ok(None),
            Err(e) => return Err(e),
        };

        tracing::trace!("  =>");
        tracing::trace!("  user_id: {:?}", user_id);
        tracing::trace!("  password_hash: {:?}", password_hash);
        tracing::trace!("  password_salt: {:?}", password_salt);
        tracing::trace!("  password_method: {:?}", password_method);

        if Self::verify_password(password, &password_hash, &password_salt, &password_method)? {
            Ok(Some(user_id))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn tx_get_user_by_id(tx: &Transaction<'_>, user_id: i64) -> Result<User> {
        struct InnerUser {
            id: i64,
            username: String,
        }

        impl FromRow for InnerUser {
            fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
                Ok(Self {
                    id: row.get("id")?,
                    username: row.get("username")?,
                })
            }
        }

        let query = Query::select_from("users")
            .all_columns()
            .condition(query::eq(query::column("id"), param(1)))
            .into_query();

        let mut user = query
            .select_maybe::<InnerUser>(tx, params![user_id])?
            .ok_or(crate::Error::UserNotFound)
            .map(|u| User {
                id: u.id,
                username: u.username,
                permissions: vec![],
            })?;

        user.permissions = Self::tx_get_user_permissions(tx, user.id)?;
        Ok(user)
    }

    pub(crate) fn tx_get_user_by_username(tx: &Transaction<'_>, username: &str) -> Result<User> {
        struct InnerUser {
            id: i64,
            username: String,
        }

        impl FromRow for InnerUser {
            fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
                Ok(Self {
                    id: row.get("id")?,
                    username: row.get("username")?,
                })
            }
        }

        let query = Query::select_from("users")
            .all_columns()
            .condition(query::eq(query::column("username"), param(1)))
            .into_query();

        let mut user = query
            .select_maybe::<InnerUser>(tx, params![username])?
            .ok_or(crate::Error::UserNotFound)
            .map(|u| User {
                id: u.id,
                username: u.username,
                permissions: vec![],
            })?;

        user.permissions = Self::tx_get_user_permissions(tx, user.id)?;
        Ok(user)
    }

    pub fn get_user_by_id(&mut self, user_id: i64) -> Result<User> {
        let tx = self.database.transaction()?;
        let user = {
            tracing::trace!("[database] get_user_by_id:");
            tracing::trace!("  user_id: {:?}", user_id);
            Self::tx_get_user_by_id(&tx, user_id)?
        };

        tx.commit()?;
        Ok(user)
    }

    pub fn get_user_by_username(&self, username: &str) -> Result<User> {
        let tx = self.database.transaction()?;
        let user = {
            tracing::trace!("[database] get_user_by_username:");
            tracing::trace!("  username: {:?}", username);
            Self::tx_get_user_by_username(&tx, username)?
        };

        tx.commit()?;
        Ok(user)
    }

    pub fn list_users(&mut self) -> Result<Vec<User>> {
        let mut users = vec![];
        let tx = self.database.transaction()?;

        {
            struct InnerUser {
                id: i64,
                username: String,
            }

            impl FromRow for InnerUser {
                fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
                    Ok(Self {
                        id: row.get("id")?,
                        username: row.get("username")?,
                    })
                }
            }

            let query = Query::select_from("users").all_columns().into_query();

            let inner_users = query.select_many::<InnerUser>(&tx, params![])?;
            for inner_user in inner_users {
                let mut user = User {
                    id: inner_user.id,
                    username: inner_user.username,
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
        let tx = self.database.transaction()?;

        {
            tracing::trace!("[database] delete_user_by_username:");
            tracing::trace!("  username: {:?}", username);

            let query = Query::delete_from("users")
                .condition(query::eq("username", param(1)))
                .into_query();

            query.delete(&tx, params![username])?;
        }

        tx.commit()?;
        Ok(())
    }
}
