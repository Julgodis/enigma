use anyhow::Result;
use clap::{Parser, Subcommand};
use enigma::Database;

#[derive(Parser)]
#[clap(version = "1.0", author = "Julgodis")]
struct Opts {
    #[clap(subcommand)]
    cmd: Command,

    #[clap(long, default_value = "enigma.db")]
    path: String,
}

#[derive(Subcommand)]
enum Command {
    /// Manage users
    User {
        #[clap(subcommand)]
        cmd: User,
    },
    /// Manage permissions
    Perm {
        #[clap(subcommand)]
        cmd: Perm,
    },
}

#[derive(Subcommand)]
enum User {
    /// Create a new user
    Create(CreateUser),
    /// Delete a user
    Delete(DeleteUser),
    /// List all users
    List,
}

#[derive(Parser)]
struct CreateUser {
    /// Username of the new user
    username: String,
    /// Password for the new user
    password: String,
    /// Email address for the new user
    email: Option<String>,
}

#[derive(Parser)]
struct DeleteUser {
    /// Username of the user to be deleted
    username: String,
}

#[derive(Subcommand)]
enum Perm {
    /// Add a permission to a user
    Add(AddPerm),
    /// Remove a permission from a user
    Remove(RemovePerm),
}

#[derive(Parser)]
struct AddPerm {
    /// Username of the user to add the permission to
    username: String,
    /// Site to add the permission to
    site: String,
    /// Permission to add
    permission: String,
}

#[derive(Parser)]
struct RemovePerm {
    /// Username of the user to remove the permission from
    username: String,
    /// Site to remove the permission from
    site: String,
    /// Permission to remove
    permission: String,
}

fn main() {
    tracing_subscriber::fmt::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(true)
        .with_thread_ids(false)
        .with_thread_names(false)
        .init();

    tracing::info!("enigma-cli (v{})", env!("CARGO_PKG_VERSION"));

    match cli() {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            tracing::error!("{:?}", e);
            std::process::exit(1);
        }
    }
}

fn cli() -> Result<()> {
    let opts: Opts = Opts::parse();
    let database = Database::new(opts.path)?;

    match opts.cmd {
        Command::User { cmd } => cli_user(database, cmd)?,
        Command::Perm { cmd } => cli_perms(database, cmd)?,
    }

    Ok(())
}

fn cli_user(mut database: Database, cmd: User) -> Result<()> {
    match cmd {
        User::Create(CreateUser {
            username,
            password,
            email,
        }) => {
            println!("create user: {:?}", username);
            database.create_user(enigma::user::CreateUser {
                username,
                password,
                email,
            })?;
        }
        User::Delete(DeleteUser { username }) => {
            println!("delete user: {:?}", username);
            database.delete_user_by_username(&username)?;
        }
        User::List => {
            let users = database.list_users()?;
            println!("found {} users:", users.len());
            for user in users {
                let perms = user
                    .permissions
                    .iter()
                    .map(|p| format!("{}:{}", p.site, p.permission))
                    .collect::<Vec<_>>()
                    .join(",");
                println!("  #{:4} | {:>30} | {}", user.id, user.username, perms);
            }
        }
    }

    Ok(())
}

fn cli_perms(mut database: Database, cmd: Perm) -> Result<()> {
    match cmd {
        Perm::Add(AddPerm {
            username,
            site,
            permission,
        }) => {
            println!("add permission: {:?} {:?} {:?}", username, site, permission);
            let user = database.get_user_by_username(&username)?;
            database.add_permission(user.id, &site, &permission)?;
        }
        Perm::Remove(RemovePerm {
            username,
            site,
            permission,
        }) => {
            println!(
                "remove permission: {:?} {:?} {:?}",
                username, site, permission
            );
            let user = database.get_user_by_username(&username)?;
            database.remove_permission(user.id, &site, &permission)?;
        }
    }

    Ok(())
}
