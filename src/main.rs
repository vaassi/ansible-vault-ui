use std::ffi::OsStr;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use cursive::{Cursive, menu};
use cursive::event::Key;
use cursive::traits::{Nameable, Resizable};
use cursive::view::SizeConstraint;
use cursive::views::{Dialog, EditView, LinearLayout, NamedView, Panel, ResizedView, SelectView, TextArea, TextView};

use crate::ansible::{decrypt_vault_from_file, encrypt_vault, VAULT_1_1_PREFIX};

mod ansible;

const VIEW_ID_CONTENT: &str = "content";
const VIEW_ID_SELECT: &str = "select";

struct Data {
    password: String,
    prev_path: PathBuf,
    path: PathBuf,
    content: String,
    selected_id: usize,
}

fn main() {
    let mut siv = cursive::default();

    siv.set_user_data(Data {
        password: String::new(),
        prev_path: PathBuf::new(),
        path: PathBuf::new(),
        content: String::new(),
        selected_id: 0,
    });

    siv.add_global_callback('q', Cursive::quit);
    siv.add_global_callback(Key::Esc, |s| s.select_menubar());

    siv.add_layer(
        Dialog::new()
            .title("Enter password")
            .padding_lrtb(1, 1, 1, 0)
            .content(
                EditView::new()
                    .secret()
                    .on_submit(|s, text| {
                        s.with_user_data(|data: &mut Data| {
                            data.password = text.to_owned();
                        });
                        check_password(s);
                    })
                    .fixed_width(32)
            )
            .button("Quit", |s| s.quit())
    );

    siv.run();
}

fn check_password(s: &mut Cursive) {
    let password = s.user_data::<Data>().unwrap().password.clone();

    if password.is_empty() {
        s.add_layer(Dialog::info("Password can't be empty."));
    } else {
        s.pop_layer();
        s.set_autohide_menu(false);
        s.menubar()
            .add_subtree(
                "File",
                menu::Tree::new()
                    .leaf("Open...", |s| {
                        s.add_layer(
                            Dialog::new()
                                .title("Enter directory path")
                                .padding_lrtb(1, 1, 1, 0)
                                .content(
                                    EditView::new()
                                        .on_submit(|s, text| {
                                            s.pop_layer();
                                            s.add_fullscreen_layer(LinearLayout::horizontal()
                                                .child(
                                                    Panel::new(ResizedView::new(
                                                        SizeConstraint::AtLeast(50),
                                                        SizeConstraint::Full,
                                                        file_picker(text).unwrap(),
                                                    )).title("File Browser")
                                                )
                                                .child(
                                                    Panel::new(ResizedView::new(
                                                        SizeConstraint::Full,
                                                        SizeConstraint::Full,
                                                        TextArea::new()
                                                            .with_name(VIEW_ID_CONTENT),
                                                    )).title("Decrypted Content")
                                                ));
                                        }).fixed_width(32)
                                )
                                .dismiss_button("Cancel")
                        );
                    })
                    .delimiter()
                    .leaf("Quit", |s| s.quit()),
            )
            .add_subtree(
                "Help",
                menu::Tree::new()
                    .leaf("About", |s| {
                        s.add_layer(Dialog::info("Ansible-Vault UI v0.1.0"))
                    }),
            );
    }
}

fn file_picker<D: AsRef<Path>>(directory: D) -> Result<NamedView<SelectView<PathBuf>>> {
    let mut select = SelectView::new();

    let parent = PathBuf::new();
    select.add_item(".", parent);

    for entry in fs::read_dir(directory)?.flatten() {
        let path = entry.path();
        // filter only files
        if path.is_file() && !(path.extension().is_some() && path.extension().unwrap() == "bkp") {
            let file = File::open(&path)?;
            let mut encrypted = "";
            if let Some(line) = BufReader::new(&file).lines().next() {
                let line = line?;
                if line == VAULT_1_1_PREFIX {
                    encrypted = "*"
                }
            }

            select.add_item(format!("{}{}", entry.file_name().into_string().unwrap(), encrypted), entry.path())
        }
    }

    Ok(select.on_select(check_content).with_name(VIEW_ID_SELECT))
}

fn check_content(s: &mut Cursive, path: &PathBuf) {
    let prev_path = s.user_data::<Data>().unwrap().prev_path.clone();
    let prev_content = s.user_data::<Data>().unwrap().content.clone();

    let selected = s.call_on_name(VIEW_ID_SELECT, |v: &mut SelectView<PathBuf>| {
        v.selected_id().unwrap()
    }).unwrap();

    if prev_path.exists() {
        let content = s.call_on_name(VIEW_ID_CONTENT, |v: &mut TextArea| {
            v.get_content().to_owned()
        }).unwrap();

        if !content.is_empty() && content != prev_content && selected != 1 {
            s.with_user_data(|data: &mut Data| {
                data.path = path.clone();
                data.content = content.trim().to_owned();
                data.selected_id = selected;
            });

            s.add_layer(
                Dialog::new()
                    .title("Close file")
                    .content(TextView::new("Save before close?"))
                    .button("Yes", |s| {
                        s.pop_layer();
                        save_encrypt_file(s).unwrap();
                    })
                    .button("No", |s| {
                        s.pop_layer();
                        load_content(s).unwrap();
                    })
            );

            return;
        }
    }

    s.with_user_data(|data: &mut Data| {
        data.path = path.clone();
        data.selected_id = selected;
    });
    load_content(s).unwrap();
}

fn load_content(s: &mut Cursive) -> Result<()> {
    let path = s.user_data::<Data>().unwrap().path.clone();
    let password = s.user_data::<Data>().unwrap().password.clone();

    // read first line to detect that this is ansible encrypted file
    if path.exists() {
        let file = File::open(&path)?;

        if let Some(line) = BufReader::new(&file).lines().next() {
            let line = line?;
            if line == VAULT_1_1_PREFIX {
                let buf = decrypt_vault_from_file(&path, &password)
                    .unwrap_or("ERROR! Decryption failed".to_string().into_bytes());
                let decrypted = String::from_utf8(buf)?;

                s.call_on_name(VIEW_ID_CONTENT, |v: &mut TextArea| {
                    v.set_content(decrypted.clone());
                });

                s.with_user_data(|data: &mut Data| {
                    data.prev_path = path;
                    data.content = decrypted;
                });
            } else {
                let buf = fs::read_to_string(&path)?;

                s.call_on_name(VIEW_ID_CONTENT, |v: &mut TextArea| {
                    v.set_content(buf.clone());
                });

                s.with_user_data(|data: &mut Data| {
                    data.prev_path = path;
                    data.content = buf;
                });
            }
        }
    } else {
        s.call_on_name(VIEW_ID_CONTENT, |v: &mut TextArea| {
            v.set_content("");
        });
    }

    Ok(())
}

fn save_encrypt_file(s: &mut Cursive) -> Result<()> {
    let prev_path = s.user_data::<Data>().unwrap().prev_path.clone();
    let password = s.user_data::<Data>().unwrap().password.clone();
    let content = s.user_data::<Data>().unwrap().content.clone();
    let selected_id = s.user_data::<Data>().unwrap().selected_id;

    // backup old file
    let bkp_path = prev_path.with_extension(format!("{}.bkp", prev_path.extension().and_then(OsStr::to_str).unwrap_or_default()));
    if bkp_path.exists() {
        fs::remove_file(&bkp_path)?;
    }
    fs::rename(&prev_path, bkp_path)?;

    // encrypt file content
    let encoded = encrypt_vault(content.as_bytes(), &password)?;
    let mut f = File::create(&prev_path)?;
    f.write_all(encoded.as_ref())?;

    // update file browser
    s.call_on_name(VIEW_ID_SELECT, |v: &mut SelectView<PathBuf>| {
        v.remove_item(selected_id - 1);
        v.insert_item(selected_id - 1, format!("{}*", prev_path.file_name().and_then(OsStr::to_str).unwrap_or_default()), prev_path)
    });

    load_content(s)?;

    Ok(())
}