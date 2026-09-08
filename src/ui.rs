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
    discovery::{DiscoveredDevice, DiscoveryBrowser},
    editor::{Editor, MAX_DRAFTS},
    network::{Command, ConnectTarget, Mode, Network, PairingPrompt},
    persistence::Store,
    state::Side,
};

const DEBOUNCE: Duration = Duration::from_millis(75);

enum Action {
    StartStop,
    Mode,
    Nearby,
    SaveName,
    Changed,
    Flush,
    TakeControl,
    CopyAll,
    ConfirmPairing,
    RejectPairing,
    Forget,
    ResetIdentity,
    Drafts,
    Close,
}

struct Ui {
    window: Window,
    mode: Choice,
    nearby: Choice,
    name: Input,
    ip: Input,
    port: Input,
    start: Button,
    confirm: Button,
    reject: Button,
    forget: Button,
    reset_identity: Button,
    phrase: Frame,
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
    discovery: Option<DiscoveryBrowser>,
    discovered: Vec<DiscoveredDevice>,
    pairing: Option<PairingPrompt>,
    store: Store,
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
    fn new(tx: mpsc::Sender<Action>, store: Store) -> Self {
        let device = store.device();
        let mut window = Window::default()
            .with_size(860, 690)
            .with_label("pair")
            .center_screen();
        window.set_color(Color::from_rgb(243, 243, 241));
        let mut layout = Flex::default_fill().column();
        layout.set_margin(14);
        layout.set_spacing(8);

        let mut identity = Flex::default().row();
        identity.set_spacing(8);
        let device_label = Frame::default().with_label("This device");
        identity.fixed(&device_label, 75);
        let mut name = Input::default();
        name.set_value(&device.name);
        name.set_tooltip("A local display name, up to 32 UTF-8 bytes.");
        let mut save_name = Button::default().with_label("Save Name");
        identity.fixed(&save_name, 90);
        let mut forget = Button::default().with_label("Forget Device");
        identity.fixed(&forget, 110);
        let mut reset_identity = Button::default().with_label("Reset Identity");
        reset_identity
            .set_tooltip("Advanced: replace this host certificate and revoke its paired peer.");
        identity.fixed(&reset_identity, 105);
        identity.end();
        layout.fixed(&identity, 30);

        let mut connection = Flex::default().row();
        connection.set_spacing(8);
        let mut mode = Choice::default();
        mode.add_choice("Host|Connect");
        mode.set_value(0);
        connection.fixed(&mode, 105);
        let mut nearby = Choice::default();
        nearby.add_choice("Manual address");
        nearby.set_value(0);
        nearby.set_tooltip("Nearby Pair hosts discovered on this LAN.");
        connection.fixed(&nearby, 210);
        let ip_label = Frame::default().with_label("IP");
        connection.fixed(&ip_label, 18);
        let mut ip = Input::default();
        ip.set_value("0.0.0.0");
        let port_label = Frame::default().with_label("Port");
        connection.fixed(&port_label, 34);
        let mut port = Input::default();
        port.set_value("47321");
        connection.fixed(&port, 70);
        let mut start = Button::default().with_label("Start Host");
        connection.fixed(&start, 105);
        connection.end();
        layout.fixed(&connection, 32);

        let mut hint = Frame::default().with_label("Start Host on one computer. Choose Connect on the other and select the nearby host. Compare the phrase once; Pair remembers the device.");
        hint.set_align(Align::Left | Align::Inside | Align::Wrap);
        hint.set_label_size(12);
        layout.fixed(&hint, 34);

        let mut verify = Flex::default().row();
        verify.set_spacing(8);
        let mut phrase = Frame::default().with_label("No pairing confirmation needed.");
        phrase.set_align(Align::Left | Align::Inside | Align::Wrap);
        phrase.set_label_size(12);
        let mut confirm = Button::default().with_label("Phrase Matches — Pair");
        verify.fixed(&confirm, 165);
        let mut reject = Button::default().with_label("Reject");
        verify.fixed(&reject, 75);
        verify.end();
        layout.fixed(&verify, 45);

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
        actions.fixed(&take, 120);
        let mut copy = Button::default().with_label("Copy All");
        actions.fixed(&copy, 90);
        let mut draft = Button::default().with_label("Drafts (0)");
        actions.fixed(&draft, 105);
        let mut owner = Frame::default().with_label("Start or connect to edit.");
        owner.set_align(Align::Left | Align::Inside | Align::Wrap);
        owner.set_label_size(12);
        actions.end();
        layout.fixed(&actions, 32);
        let mut status = Frame::default().with_label("Not connected.");
        status.set_align(Align::Left | Align::Inside | Align::Wrap);
        status.set_label_size(12);
        layout.fixed(&status, 46);
        layout.end();
        window.end();
        window.resizable(&layout);
        window.size_range(730, 500, 0, 0);

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
        button_callback(&mut save_name, &tx, || Action::SaveName);
        button_callback(&mut forget, &tx, || Action::Forget);
        button_callback(&mut reset_identity, &tx, || Action::ResetIdentity);
        button_callback(&mut confirm, &tx, || Action::ConfirmPairing);
        button_callback(&mut reject, &tx, || Action::RejectPairing);
        button_callback(&mut take, &tx, || Action::TakeControl);
        button_callback(&mut copy, &tx, || Action::CopyAll);
        button_callback(&mut draft, &tx, || Action::Drafts);
        mode.set_callback({
            let tx = tx.clone();
            move |_| {
                let _ = tx.send(Action::Mode);
            }
        });
        nearby.set_callback({
            let tx = tx.clone();
            move |_| {
                let _ = tx.send(Action::Nearby);
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
            nearby,
            name,
            ip,
            port,
            start,
            confirm,
            reject,
            forget,
            reset_identity,
            phrase,
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
            discovery: None,
            discovered: Vec::new(),
            pairing: None,
            store,
            tx,
            timer_armed: false,
            last_change: Instant::now(),
            notice: String::new(),
            network_status: "Not connected.".into(),
            stopping: false,
        }
    }

    fn ensure_discovery(&mut self) {
        if self.mode.value() == 1 && self.discovery.is_none() {
            match DiscoveryBrowser::start(app::awake) {
                Ok(browser) => self.discovery = Some(browser),
                Err(error) => self.notice = error,
            }
        } else if self.mode.value() == 0 {
            self.discovery = None;
            self.discovered.clear();
        }
    }

    fn discovery_update(&mut self) -> bool {
        let devices = self.discovery.as_mut().and_then(|browser| {
            if browser.updates.has_changed().unwrap_or(true) {
                Some(browser.updates.borrow_and_update().clone())
            } else {
                None
            }
        });
        let Some(devices) = devices else { return false };
        if devices == self.discovered {
            return false;
        }
        let previously_selected = (self.nearby.value() > 0)
            .then(|| self.discovered.get((self.nearby.value() - 1) as usize))
            .flatten()
            .map(|device| device.id.clone());
        self.discovered = devices;
        self.nearby.clear();
        self.nearby.add_choice("Manual address");
        let trusted = self.store.trusted_host();
        for device in &self.discovered {
            let suffix = if trusted.as_ref().is_some_and(|host| host.id == device.id) {
                " (remembered)"
            } else {
                ""
            };
            self.nearby.add_choice(&format!(
                "{} — {}{}",
                device.name,
                device.address.ip(),
                suffix
            ));
        }
        let preferred = previously_selected
            .or_else(|| trusted.as_ref().map(|host| host.id.clone()))
            .or_else(|| (self.discovered.len() == 1).then(|| self.discovered[0].id.clone()));
        let selected = preferred
            .and_then(|id| self.discovered.iter().position(|device| device.id == id))
            .map_or(0, |index| index as i32 + 1);
        self.nearby.set_value(selected);
        self.choose_nearby();
        true
    }

    fn choose_nearby(&mut self) {
        if self.nearby.value() > 0
            && let Some(device) = self.discovered.get((self.nearby.value() - 1) as usize)
        {
            self.ip.set_value(&device.address.ip().to_string());
            self.port.set_value(&device.address.port().to_string());
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
        self.store.set_name(&self.name.value())?;
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
        if port == 0 || ip.is_multicast() {
            return Err("Choose a unicast address and port from 1 to 65535.".into());
        }
        let address = SocketAddr::new(ip, port);
        let side = if self.mode.value() == 0 {
            Side::Host
        } else {
            Side::Peer
        };
        let mode = if side == Side::Host {
            Mode::Host {
                address,
                text: self.model.text.clone(),
                store: self.store.clone(),
            }
        } else {
            if ip.is_unspecified() {
                return Err("Enter the host's LAN IP or select a nearby host.".into());
            }
            let selected = (self.nearby.value() > 0)
                .then(|| self.discovered.get((self.nearby.value() - 1) as usize))
                .flatten();
            let trusted = self.store.trusted_host();
            let pairing = trusted.as_ref().and_then(|host| {
                let selected_matches = selected.is_none_or(|device| device.id == host.id);
                selected_matches.then(|| host.pairing.clone())
            });
            if let (Some(host), Some(saved_pairing)) = (&trusted, &pairing)
                && host.address != address
            {
                self.store.trust_host(
                    host.id.clone(),
                    host.name.clone(),
                    address,
                    saved_pairing.clone(),
                )?;
            }
            Mode::Connect {
                target: ConnectTarget {
                    address,
                    id: selected
                        .map(|d| d.id.clone())
                        .or_else(|| trusted.as_ref().map(|h| h.id.clone())),
                    name: selected
                        .map(|d| d.name.clone())
                        .or_else(|| trusted.as_ref().map(|h| h.name.clone())),
                    pairing,
                },
                store: self.store.clone(),
            }
        };
        self.discovery = None;
        self.network = Some(
            Network::start(mode, app::awake).map_err(|_| "Could not start the network thread.")?,
        );
        self.model.start(side);
        self.stopping = false;
        self.network_status = "Starting...".into();
        Ok(())
    }

    fn command(&mut self, command: Command) -> Result<(), String> {
        self.network
            .as_ref()
            .ok_or("Start or connect first.")?
            .commands
            .try_send(command)
            .map_err(|_| {
                "Network is busy or stopped. Local text is retained; retry when ready.".into()
            })
    }

    fn act(&mut self, action: Action) -> Result<bool, String> {
        match action {
            Action::Mode => {
                self.nearby.set_value(0);
                if self.mode.value() == 0 {
                    self.ip.set_value("0.0.0.0");
                } else if let Some(host) = self.store.trusted_host() {
                    self.ip.set_value(&host.address.ip().to_string());
                    self.port.set_value(&host.address.port().to_string());
                } else {
                    self.ip.set_value("127.0.0.1");
                }
                self.ensure_discovery();
            }
            Action::Nearby => self.choose_nearby(),
            Action::SaveName => {
                self.store.set_name(&self.name.value())?;
                self.notice = "Device name saved.".into();
            }
            Action::Forget => {
                if self.model.running {
                    return Err("Stop Pair before forgetting a device.".into());
                }
                if self.mode.value() == 0 {
                    self.store.forget_peer()?;
                    self.notice = "Paired peer forgotten and its token revoked.".into();
                } else {
                    self.store.forget_host()?;
                    self.notice = "Remembered host forgotten.".into();
                }
            }
            Action::ResetIdentity => {
                if self.model.running {
                    return Err("Stop Pair before resetting its host identity.".into());
                }
                if dialog::choice2_default(
                    "Reset this host certificate and revoke its paired peer? Both computers must pair again.",
                    "Cancel",
                    "Reset Identity",
                    "",
                ) == Some(1)
                {
                    self.store.reset_host_identity()?;
                    self.notice = "Host identity reset. Pair this computer again.".into();
                }
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
            Action::ConfirmPairing => self.command(Command::ConfirmPairing)?,
            Action::RejectPairing => self.command(Command::RejectPairing)?,
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
        let view = self.network.as_mut().and_then(|network| {
            if network.updates.has_changed().unwrap_or(true) {
                Some(network.updates.borrow_and_update().clone())
            } else {
                None
            }
        });
        let Some(view) = view else { return false };
        let draft_count = self.model.drafts.len();
        self.model.connection(view.connected, view.running);
        if let Some(snapshot) = view.snapshot {
            self.model.receive(snapshot, view.sync_serial);
        }
        self.pairing = view.pairing;
        self.network_status = view.status;
        if self.model.drafts.len() > draft_count {
            self.notice =
                "Unacknowledged local text saved in Drafts. The shared note follows the host."
                    .into();
        }
        if !view.running {
            self.stopping = false;
            self.network = None;
            self.ensure_discovery();
        }
        self.schedule_flush();
        true
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
            self.nearby.deactivate();
            self.name.deactivate();
            self.ip.deactivate();
            self.port.deactivate();
            self.start
                .set_label(if self.stopping { "Stopping..." } else { "Stop" });
        } else {
            self.mode.activate();
            self.name.activate();
            self.ip.activate();
            self.port.activate();
            if self.mode.value() == 1 {
                self.nearby.activate();
            } else {
                self.nearby.deactivate();
            }
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
        if let Some(prompt) = &self.pairing {
            self.phrase
                .set_label(&format!("UNVERIFIED — compare exactly:\n{}", prompt.phrase));
            self.phrase
                .set_tooltip(&format!("Full SHA-256 fingerprint: {}", prompt.fingerprint));
            if prompt.local_confirmed {
                self.confirm.deactivate();
            } else {
                self.confirm.activate();
            }
            self.reject.activate();
        } else {
            self.phrase.set_label("No pairing confirmation needed.");
            self.phrase.set_tooltip("");
            self.confirm.deactivate();
            self.reject.deactivate();
        }
        let other_owns = self
            .model
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.owner != self.model.side);
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
        let has_saved = if self.mode.value() == 0 {
            self.store.has_trusted_peer()
        } else {
            self.store.trusted_host().is_some()
        };
        if !self.model.running && has_saved {
            self.forget.activate();
        } else {
            self.forget.deactivate();
        }
        if !self.model.running && self.mode.value() == 0 {
            self.reset_identity.activate();
        } else {
            self.reset_identity.deactivate();
        }
        let ownership = if self.model.drafts.len() == MAX_DRAFTS {
            "Draft storage full. Copy, restore, or discard one to continue."
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
        let mut hint = Frame::default().with_label(
            "Drafts stay in memory until you close Pair. Restore requires editing control.",
        );
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
            move |choice| {
                selection.set(choice.value() as usize);
                buffer.set_text(&drafts[selection.get()]);
            }
        });
        copy.set_callback({
            let buffer = buffer.clone();
            move |_| app::copy(&buffer.text())
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
        self.network_update();
        match result.get() {
            1 => match self.model.restore_draft(selection.get()) {
                Ok(()) => {
                    self.last_change = Instant::now();
                    self.schedule_flush();
                }
                Err(error) => self.notice = error.into(),
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
    let store = match Store::load_default() {
        Ok(store) => store,
        Err(error) => {
            dialog::alert_default(&error);
            return;
        }
    };
    let (tx, rx) = mpsc::channel();
    let mut ui = Ui::new(tx, store);
    ui.render();
    ui.window.show();
    while application.wait() {
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
        if ui.discovery_update() || ui.network_update() || changed {
            ui.render();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pair::{protocol::MAX_NOTE_BYTES, state::Authority};

    #[test]
    fn native_widgets_preserve_text_and_gate_editing() {
        let _app = app::App::default();
        let directory = std::env::temp_dir().join(format!("pair-ui-test-{}", std::process::id()));
        let path = directory.join("state.json");
        let _ = std::fs::remove_dir_all(&directory);
        let store = Store::load(path.clone()).unwrap();
        let (tx, _rx) = mpsc::channel();
        let mut ui = Ui::new(tx, store);
        let mut authority = Authority::new(String::new()).unwrap();
        ui.model.start(Side::Host);
        ui.model.receive(authority.snapshot.clone(), 1);
        ui.render();
        assert!(ui.editor.visible());
        let original = "\t  print('梨 🍐 café')\r\n\n  end\n";
        ui.buffer.set_text(original);
        ui.act(Action::Changed).unwrap();
        assert_eq!(ui.model.text, original);
        ui.buffer.set_text(&"a".repeat(MAX_NOTE_BYTES + 1));
        assert!(ui.act(Action::Changed).is_err());
        ui.render();
        assert_eq!(ui.buffer.text(), original);
        authority.take_control(Side::Peer);
        ui.model.receive(authority.snapshot, 1);
        ui.render();
        assert!(!ui.editor.visible());
        assert_eq!(ui.model.drafts, vec![original]);
        app::delete_widget(ui.window);
        let _ = std::fs::remove_dir_all(directory);
    }
}
