use std::{
    cell::Cell,
    net::{IpAddr, SocketAddr},
    rc::Rc,
    sync::mpsc,
    time::{Duration, Instant},
};

use fltk::{
    app,
    button::Button,
    dialog,
    enums::{Align, Color, Font, FrameType},
    frame::Frame,
    group::{Flex, Group},
    input::Input,
    menu::Choice,
    prelude::*,
    text::{TextBuffer, TextDisplay, TextEditor},
    window::Window,
};
use pair::{
    editor::{Editor, MAX_DRAFTS},
    network::{Command, Mode, Network},
    state::Side,
    tls::Pairing,
};

const DEBOUNCE: Duration = Duration::from_millis(75);

enum Action {
    StartStop,
    Mode,
    Changed,
    Flush,
    TakeControl,
    CopyAll,
    CopyCode,
    Drafts,
    Close,
}

struct Ui {
    window: Window,
    mode: Choice,
    ip: Input,
    port: Input,
    code: Input,
    start: Button,
    take: Button,
    draft: Button,
    owner: Frame,
    status: Frame,
    editor: TextEditor,
    viewer: TextDisplay,
    buffer: TextBuffer,
    suppress: Rc<Cell<bool>>,
    model: Editor,
    network: Option<Network>,
    tx: mpsc::Sender<Action>,
    timer_armed: bool,
    last_change: Instant,
    notice: String,
    network_status: String,
    stopping: bool,
}

fn button_callback(button: &mut Button, tx: &mpsc::Sender<Action>, action: fn() -> Action) {
    let tx = tx.clone();
    button.set_callback(move |_| {
        let _ = tx.send(action());
    });
}

impl Ui {
    fn new(tx: mpsc::Sender<Action>) -> Self {
        let mut window = Window::default()
            .with_size(840, 630)
            .with_label("pair")
            .center_screen();
        window.set_color(Color::from_rgb(243, 243, 241));
        let mut layout = Flex::default_fill().column();
        layout.set_margin(14);
        layout.set_spacing(10);

        let mut connection = Flex::default().row();
        connection.set_spacing(8);
        let mut mode = Choice::default();
        mode.add_choice("Host|Connect");
        mode.set_value(0);
        mode.set_tooltip("Host owns the shared state. Connect joins one host.");
        connection.fixed(&mode, 112);
        let ip_label = Frame::default().with_label("IP");
        connection.fixed(&ip_label, 20);
        let mut ip = Input::default();
        ip.set_value("0.0.0.0");
        ip.set_tooltip("Host: local bind IP (0.0.0.0 for all IPv4 interfaces). Connect: host's numeric LAN IP.");
        let port_label = Frame::default().with_label("Port");
        connection.fixed(&port_label, 36);
        let mut port = Input::default();
        port.set_value("47321");
        connection.fixed(&port, 75);
        let mut start = Button::default().with_label("Start Host");
        connection.fixed(&start, 110);
        connection.end();
        layout.fixed(&connection, 32);

        let mut pairing_row = Flex::default().row();
        pairing_row.set_spacing(8);
        let pairing_label = Frame::default().with_label("Pairing code");
        pairing_row.fixed(&pairing_label, 85);
        let mut code = Input::default();
        code.set_readonly(true);
        code.set_text_font(Font::Courier);
        code.set_text_size(12);
        code.set_tooltip("Copy from the host through a trusted channel. Contains a certificate fingerprint and a secret token.");
        let mut copy_code = Button::default().with_label("Copy Code");
        pairing_row.fixed(&copy_code, 100);
        pairing_row.end();
        layout.fixed(&pairing_row, 30);

        let mut hint = Frame::default().with_label(
            "Start Host on one computer. On the other, choose Connect and enter the host's LAN IP and pairing code. Text stays in memory; use Copy All to keep it.",
        );
        hint.set_align(Align::Left | Align::Inside | Align::Wrap);
        hint.set_label_size(12);
        layout.fixed(&hint, 38);

        // Flex sizes its children at end(); give the parent a valid initial
        // size before TextDisplay/TextEditor::default_fill inspects it.
        let area = Group::default().with_size(100, 100);
        let mut buffer = TextBuffer::default();
        buffer.set_tab_distance(4);
        let mut viewer = TextDisplay::default_fill();
        viewer.set_buffer(buffer.clone());
        viewer.set_text_font(Font::Courier);
        viewer.set_text_size(15);
        viewer.set_frame(FrameType::DownBox);
        let mut editor = TextEditor::default_fill();
        editor.set_buffer(buffer.clone());
        editor.set_text_font(Font::Courier);
        editor.set_text_size(15);
        editor.set_frame(FrameType::DownBox);
        editor.set_tab_nav(false);
        editor.hide();
        area.end();
        area.resizable(&viewer);

        let mut actions = Flex::default().row();
        actions.set_spacing(8);
        let mut take = Button::default().with_label("Take Control");
        actions.fixed(&take, 125);
        let mut copy = Button::default().with_label("Copy All");
        actions.fixed(&copy, 100);
        let mut draft = Button::default().with_label("Drafts (0)");
        actions.fixed(&draft, 110);
        let mut owner = Frame::default().with_label("Start or connect to edit.");
        owner.set_align(Align::Left | Align::Inside | Align::Wrap);
        owner.set_label_size(12);
        actions.end();
        layout.fixed(&actions, 32);

        let mut status = Frame::default().with_label("Not connected.");
        status.set_align(Align::Left | Align::Inside | Align::Wrap);
        status.set_label_size(12);
        layout.fixed(&status, 44);
        layout.end();
        window.end();
        window.resizable(&layout);
        window.size_range(720, 450, 0, 0);

        let suppress = Rc::new(Cell::new(false));
        buffer.add_modify_callback({
            let tx = tx.clone();
            let suppress = suppress.clone();
            move |_, inserted, deleted, _, _| {
                if !suppress.get() && (inserted != 0 || deleted != 0) {
                    let _ = tx.send(Action::Changed);
                }
            }
        });
        button_callback(&mut start, &tx, || Action::StartStop);
        button_callback(&mut take, &tx, || Action::TakeControl);
        button_callback(&mut copy, &tx, || Action::CopyAll);
        button_callback(&mut copy_code, &tx, || Action::CopyCode);
        button_callback(&mut draft, &tx, || Action::Drafts);
        mode.set_callback({
            let tx = tx.clone();
            move |_| {
                let _ = tx.send(Action::Mode);
            }
        });
        window.set_callback({
            let tx = tx.clone();
            move |_| {
                let _ = tx.send(Action::Close);
            }
        });

        Self {
            window,
            mode,
            ip,
            port,
            code,
            start,
            take,
            draft,
            owner,
            status,
            editor,
            viewer,
            buffer,
            suppress,
            model: Editor::default(),
            network: None,
            tx,
            timer_armed: false,
            last_change: Instant::now(),
            notice: String::new(),
            network_status: "Not connected.".into(),
            stopping: false,
        }
    }

    fn schedule_flush(&mut self) {
        if !self.timer_armed && self.model.needs_flush() {
            self.timer_armed = true;
            let delay = DEBOUNCE.saturating_sub(self.last_change.elapsed());
            let tx = self.tx.clone();
            app::add_timeout3(delay.as_secs_f64().max(0.001), move |_| {
                let _ = tx.send(Action::Flush);
            });
        }
    }

    fn start_stop(&mut self) -> Result<(), String> {
        if self.model.running {
            if let Some(network) = &self.network {
                network.stop();
                self.stopping = true;
                self.notice = "Stopping...".into();
            }
            return Ok(());
        }
        let ip: IpAddr = self
            .ip
            .value()
            .trim()
            .parse()
            .map_err(|_| "Enter a numeric IPv4 or IPv6 address (no hostname or brackets).")?;
        let port: u16 = self
            .port
            .value()
            .trim()
            .parse()
            .map_err(|_| "Port must be an integer from 1 to 65535.")?;
        if port == 0 {
            return Err("Choose a port from 1 to 65535.".into());
        }
        if ip.is_multicast() {
            return Err("Use a unicast local network address.".into());
        }
        let address = SocketAddr::new(ip, port);
        let side = if self.mode.value() == 0 {
            Side::Host
        } else {
            Side::Peer
        };
        let mode = match side {
            Side::Host => Mode::Host {
                address,
                text: self.model.text.clone(),
            },
            Side::Peer => {
                if ip.is_unspecified() {
                    return Err(
                        "Enter the host's actual LAN IP; 0.0.0.0 and :: are bind addresses.".into(),
                    );
                }
                Mode::Connect {
                    address,
                    pairing: Pairing::parse(&self.code.value())?,
                }
            }
        };
        self.network = Some(
            Network::start(mode, app::awake).map_err(|_| "Could not start the network thread.")?,
        );
        self.model.start(side);
        self.stopping = false;
        self.network_status = "Starting...".into();
        if side == Side::Host {
            self.code.set_value("");
        }
        Ok(())
    }

    fn command(&mut self, command: Command) -> Result<(), String> {
        self.network
            .as_ref()
            .ok_or("Start or connect first.")?
            .commands
            .try_send(command)
            .map_err(|_| {
                "Network is busy or stopped. Local text is retained; retrying when ready.".into()
            })
    }

    fn act(&mut self, action: Action) -> Result<bool, String> {
        match action {
            Action::Mode => {
                self.code.set_value("");
                self.code.set_readonly(self.mode.value() == 0);
                self.ip.set_value(if self.mode.value() == 0 {
                    "0.0.0.0"
                } else {
                    "127.0.0.1"
                });
            }
            Action::StartStop => self.start_stop()?,
            Action::Changed => {
                self.last_change = Instant::now();
                self.model
                    .set_text(self.buffer.text())
                    .map_err(str::to_string)?;
                self.notice.clear();
                self.schedule_flush();
            }
            Action::Flush => {
                self.timer_armed = false;
                if self.last_change.elapsed() >= DEBOUNCE
                    && let Some(edit) = self.model.prepare_edit()
                    && let Err(error) = self.command(Command::Edit(edit))
                {
                    self.model.enqueue_failed();
                    self.last_change = Instant::now();
                    self.schedule_flush();
                    return Err(error);
                }
                self.schedule_flush();
            }
            Action::TakeControl => self.command(Command::TakeControl)?,
            Action::CopyAll => {
                app::copy(&self.model.text);
                self.notice = "Copied the whole note.".into();
            }
            Action::CopyCode => {
                if !self.code.value().is_empty() {
                    app::copy(&self.code.value());
                    self.notice = "Copied pairing code. Share it through a trusted channel.".into();
                }
            }
            Action::Drafts => self.show_drafts(),
            Action::Close => {
                if (self.model.has_unsent() || !self.model.drafts.is_empty())
                    && dialog::choice2_default(
                        "Unsent edits or recovery drafts are still in memory. Copy them before closing to keep them.",
                        "Keep open",
                        "Close and discard",
                        "",
                    ) != Some(1)
                {
                    return Ok(false);
                }
                if let Some(network) = &self.network {
                    network.stop();
                }
                self.window.hide();
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn network_update(&mut self) -> bool {
        let view = self.network.as_mut().and_then(|n| {
            if n.updates.has_changed().unwrap_or(true) {
                Some(n.updates.borrow_and_update().clone())
            } else {
                None
            }
        });
        if let Some(view) = view {
            let draft_count = self.model.drafts.len();
            self.model.connection(view.connected, view.running);
            if let Some(snapshot) = view.snapshot {
                self.model.receive(snapshot, view.sync_serial);
            }
            if let Some(code) = view.pairing_code {
                self.code.set_value(&code);
            }
            self.network_status = view.status;
            if self.model.drafts.len() > draft_count {
                self.notice =
                    "Unacknowledged local text saved in Drafts. The shared note follows the host."
                        .into();
            }
            if !view.running {
                self.stopping = false;
                // Release the sender only after observing the final view.
                self.network = None;
            }
            self.schedule_flush();
            true
        } else {
            false
        }
    }

    fn render(&mut self) {
        if self.buffer.text() != self.model.text {
            self.suppress.set(true);
            let cursor = self
                .editor
                .insert_position()
                .min(self.model.text.len() as i32);
            self.buffer.set_text(&self.model.text);
            self.editor
                .set_insert_position(self.buffer.utf8_align(cursor));
            self.suppress.set(false);
        }
        if self.model.can_edit() && !self.stopping {
            if !self.editor.visible() {
                self.viewer.hide();
                self.editor.show();
            }
        } else if !self.viewer.visible() {
            self.editor.hide();
            self.viewer.show();
        }
        if self.model.running {
            self.mode.deactivate();
            self.ip.deactivate();
            self.port.deactivate();
            self.code.set_readonly(true);
            self.start
                .set_label(if self.stopping { "Stopping..." } else { "Stop" });
        } else {
            self.mode.activate();
            self.ip.activate();
            self.port.activate();
            self.code.set_readonly(self.mode.value() == 0);
            self.start.set_label(if self.mode.value() == 0 {
                "Start Host"
            } else {
                "Connect"
            });
        }
        if self.stopping {
            self.start.deactivate();
        } else {
            self.start.activate();
        }
        let other_owns = self
            .model
            .snapshot
            .as_ref()
            .is_some_and(|s| s.owner != self.model.side);
        if self.model.running
            && !self.stopping
            && other_owns
            && (self.model.side == Side::Host || self.model.connected)
        {
            self.take.activate();
        } else {
            self.take.deactivate();
        }
        self.draft
            .set_label(&format!("Drafts ({})", self.model.drafts.len()));
        if self.model.drafts.is_empty() {
            self.draft.deactivate();
        } else {
            self.draft.activate();
        }
        let ownership = if self.model.drafts.len() == MAX_DRAFTS {
            "Draft storage full. Copy/restore/discard a draft to continue."
        } else if !self.model.running {
            "Start or connect to edit."
        } else if self.model.side == Side::Peer && !self.model.connected {
            "Disconnected · read only"
        } else if self.model.can_edit() {
            if self.model.has_unsent() {
                "You have control · syncing..."
            } else {
                "You have control · saved at host"
            }
        } else {
            "Other computer has control · read only"
        };
        self.owner.set_label(ownership);
        self.status.set_label(&if self.notice.is_empty() {
            self.network_status.clone()
        } else {
            format!("{}\n{}", self.notice, self.network_status)
        });
    }

    fn show_drafts(&mut self) {
        if self.model.drafts.is_empty() {
            return;
        }
        let mut window = Window::default()
            .with_size(690, 460)
            .with_label("pair — recovery drafts")
            .center_screen();
        let mut layout = Flex::default_fill().column();
        layout.set_margin(12);
        layout.set_spacing(8);
        let mut select = Choice::default();
        for (i, text) in self.model.drafts.iter().enumerate() {
            select.add_choice(&format!("Draft {} ({} UTF-8 bytes)", i + 1, text.len()));
        }
        select.set_value((self.model.drafts.len() - 1) as i32);
        layout.fixed(&select, 30);
        let mut buffer = TextBuffer::default();
        buffer.set_text(&self.model.drafts[select.value() as usize]);
        let mut display = TextDisplay::default();
        display.set_buffer(buffer.clone());
        display.set_text_font(Font::Courier);
        display.set_text_size(14);
        let mut hint = Frame::default().with_label("Drafts stay in memory until you close pair. Restore replaces the shared note and requires editing control.");
        hint.set_align(Align::Left | Align::Inside | Align::Wrap);
        hint.set_label_size(12);
        layout.fixed(&hint, 36);
        let row = Flex::default().row();
        let mut copy = Button::default().with_label("Copy Draft");
        let mut restore = Button::default().with_label("Restore");
        let mut discard = Button::default().with_label("Discard Draft");
        let mut close = Button::default().with_label("Close");
        row.end();
        layout.fixed(&row, 32);
        layout.end();
        window.end();
        window.resizable(&layout);
        window.make_modal(true);
        let selection = Rc::new(Cell::new(select.value() as usize));
        let result = Rc::new(Cell::new(0));
        select.set_callback({
            let selection = selection.clone();
            let drafts = self.model.drafts.clone();
            let mut buffer = buffer.clone();
            move |c| {
                selection.set(c.value() as usize);
                buffer.set_text(&drafts[selection.get()]);
            }
        });
        copy.set_callback({
            let buffer = buffer.clone();
            move |_| {
                app::copy(&buffer.text());
            }
        });
        restore.set_callback({
            let result = result.clone();
            let mut window = window.clone();
            move |_| {
                result.set(1);
                window.hide();
            }
        });
        discard.set_callback({
            let result = result.clone();
            let mut window = window.clone();
            move |_| {
                result.set(2);
                window.hide();
            }
        });
        close.set_callback({
            let mut window = window.clone();
            move |_| window.hide()
        });
        window.show();
        while window.shown() {
            app::wait();
        }
        // Network can keep running during the modal. Apply its newest snapshot
        // before deciding if restoring is allowed; never restore on stale control.
        self.network_update();
        match result.get() {
            1 => match self.model.restore_draft(selection.get()) {
                Ok(()) => {
                    self.last_change = Instant::now();
                    self.schedule_flush();
                }
                Err(error) => {
                    self.notice = error.into();
                }
            },
            2 => {
                self.model.drafts.remove(selection.get());
            }
            _ => {}
        }
        app::delete_widget(window);
    }
}

pub fn run() {
    let application = app::App::default().with_scheme(app::Scheme::Base);
    app::set_font_size(14);
    let (tx, rx) = mpsc::channel();
    let mut ui = Ui::new(tx);
    ui.render();
    ui.window.show();
    while application.wait() {
        // Capture actual keystrokes before applying a simultaneously arriving
        // control/snapshot notification, so losing control cannot lose text.
        let mut changed = false;
        while let Ok(action) = rx.try_recv() {
            changed = true;
            if !matches!(action, Action::Changed | Action::Flush | Action::Close) {
                ui.notice.clear();
            }
            match ui.act(action) {
                Ok(true) => return,
                Err(error) => ui.notice = error,
                _ => {}
            }
        }
        // Updating labels damages widgets and can itself wake FLTK. Rendering
        // on every wake would create a redraw loop, even with no user input.
        if ui.network_update() || changed {
            ui.render();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pair::{protocol::MAX_NOTE_BYTES, state::Authority};

    #[test]
    fn native_widgets_construct_preserve_text_and_gate_editing() {
        let _app = app::App::default();
        let (tx, _rx) = mpsc::channel();
        let mut ui = Ui::new(tx);
        let mut authority = Authority::new(String::new()).unwrap();
        ui.model.start(Side::Host);
        ui.model.receive(authority.snapshot.clone(), 1);
        ui.render();
        assert!(ui.editor.visible());
        assert!(!ui.viewer.visible());
        let original = "\t  print('梨 🍐 café')\r\n\n  end\n";
        ui.buffer.set_text(original);
        ui.act(Action::Changed).unwrap();
        assert_eq!(ui.model.text, original);
        ui.render();
        assert_eq!(ui.buffer.text(), original);

        ui.buffer.set_text(&"a".repeat(MAX_NOTE_BYTES + 1));
        assert!(ui.act(Action::Changed).is_err());
        ui.render();
        assert_eq!(ui.buffer.text(), original);

        authority.take_control(Side::Peer);
        ui.model.receive(authority.snapshot.clone(), 1);
        ui.render();
        assert!(!ui.editor.visible());
        assert!(ui.viewer.visible());
        assert_eq!(ui.model.drafts, vec![original]);

        // A worker may publish its error and close the watch sender before the
        // UI wakes. The final error must still unlock the connection controls.
        ui.model.connection(false, false);
        let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        ui.ip.set_value("127.0.0.1");
        ui.port
            .set_value(&busy.local_addr().unwrap().port().to_string());
        ui.start_stop().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while ui.model.running && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
            ui.network_update();
        }
        assert!(!ui.model.running);
        assert!(ui.network.is_none());
        assert!(ui.network_status.contains("already in use"));
        app::delete_widget(ui.window);
    }
}
