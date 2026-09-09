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
    dialog, draw,
    enums::{Align, Color, Font, FrameType, Shortcut},
    frame::Frame,
    group::Group,
    input::Input,
    menu::{Choice, MenuBar},
    prelude::*,
    text::{TextBuffer, TextDisplay, TextEditor},
    window::Window,
};
use pair::{
    discovery::{DiscoveredDevice, DiscoveryBrowser},
    editor::{Editor, MAX_DRAFTS},
    network::{Command, ConnectTarget, Mode, Network, PairingPrompt, ordered_addresses},
    persistence::Store,
    state::Side,
};

const DEBOUNCE: Duration = Duration::from_millis(20);
const PORT: &str = "47321";
const BG: Color = Color::from_rgb(238, 237, 231);
const PANEL: Color = Color::from_rgb(202, 201, 194);
const FIELD: Color = Color::from_rgb(248, 247, 242);
const GREEN: Color = Color::from_rgb(36, 122, 69);
const MARGIN: i32 = 16;
const MENU_H: i32 = 24;
const STATUS_H: i32 = 28;
const LANDING_INSET: i32 = 135;
const CARD_GAP: i32 = 40;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Landing,
    Host,
    Connect,
    Workspace,
}

enum Action {
    OpenHost,
    OpenConnect,
    Back,
    ConnectNearby,
    ConnectManual,
    Refresh,
    ToggleHelp,
    ToggleHostAdvanced,
    SaveName,
    SaveConnectName,
    RemovePeer,
    ForgetHost,
    ResetIdentity,
    Changed,
    Flush,
    TakeControl,
    CopyAll,
    ConfirmPairing,
    RejectPairing,
    Disconnect,
    Drafts,
    Close,
}

struct Ui {
    window: Window,
    landing: Group,
    host: Group,
    connect: Group,
    workspace: Group,
    screen: Screen,
    host_name: Input,
    host_port: Input,
    host_advanced: Group,
    host_status: Frame,
    host_phrase: Frame,
    host_confirm: Button,
    host_reject: Button,
    peers: Choice,
    remove_peer: Button,
    nearby: Choice,
    connect_name: Input,
    connect_status: Frame,
    connect_phrase: Frame,
    connect_confirm: Button,
    connect_reject: Button,
    help_group: Group,
    manual_ip: Input,
    manual_port: Input,
    workspace_title: Frame,
    workspace_status: Frame,
    owner: Frame,
    take: Button,
    draft: Button,
    editor: TextEditor,
    viewer: TextDisplay,
    buffer: TextBuffer,
    suppress: Rc<Cell<bool>>,
    model: Editor,
    network: Option<Network>,
    discovery: Option<DiscoveryBrowser>,
    discovered: Vec<DiscoveredDevice>,
    targets: Vec<ConnectTarget>,
    active_target_id: Option<String>,
    pairing: Option<PairingPrompt>,
    store: Store,
    tx: mpsc::Sender<Action>,
    timer_armed: bool,
    last_change: Instant,
    notice: String,
    network_status: String,
}

fn callback(button: &mut Button, tx: &mpsc::Sender<Action>, action: fn() -> Action) {
    let tx = tx.clone();
    button.set_callback(move |_| {
        let _ = tx.send(action());
    });
}
fn button_style(button: &mut Button, primary: bool) {
    button.set_frame(FrameType::UpBox);
    button.set_color(if primary {
        Color::from_rgb(224, 230, 218)
    } else {
        PANEL
    });
    button.set_label_color(Color::Black);
    button.set_selection_color(GREEN);
    button.set_label_size(13);
}
fn field_style<W: WidgetExt>(widget: &mut W) {
    widget.set_frame(FrameType::DownBox);
    widget.set_color(FIELD);
    widget.set_label_color(Color::from_rgb(65, 65, 62));
}
fn recessed(mut frame: Frame) -> Frame {
    frame.set_frame(FrameType::DownBox);
    frame.set_color(FIELD);
    frame.set_label_color(Color::from_rgb(65, 65, 62));
    frame
}
fn panel(mut group: Group) -> Group {
    group.set_frame(FrameType::EngravedBox);
    group.set_color(PANEL);
    group
}
fn heading(mut frame: Frame, text: &str, size: i32) {
    frame.set_label(text);
    frame.set_label_size(size);
    frame.set_align(Align::Center | Align::Inside);
}
fn icon(mut frame: Frame, host: bool) {
    frame.draw(move |f| {
        draw::set_draw_color(Color::from_rgb(45, 45, 42));
        let (x, y, w) = (f.x(), f.y(), f.w());
        if host {
            draw::draw_pie(x + w / 2 - 11, y + 10, 22, 22, 0., 360.);
            draw::draw_arc(x + w / 2 - 31, y + 29, 62, 48, 180., 360.);
            draw::draw_line(x + w / 2 - 31, y + 53, x + w / 2 + 31, y + 53);
        } else {
            let sw = 58;
            draw::draw_rect(x + (w - sw) / 2, y + 11, sw, 39);
            draw::draw_rectf(x + (w - 22) / 2, y + 21, 22, 15);
            draw::draw_line(x + w / 2, y + 50, x + w / 2, y + 59);
            draw::draw_line(x + w / 2 - 18, y + 59, x + w / 2 + 18, y + 59);
        }
    });
}
fn choose_font() {
    let fonts = app::fonts();
    let choices: &[&str] = if cfg!(target_os = "windows") {
        &["MS Reference Sans Serif", "Segoe UI"]
    } else if cfg!(target_os = "macos") {
        &["MS Reference Sans Serif", "Helvetica Neue"]
    } else {
        &["MS Reference Sans Serif", "DejaVu Sans"]
    };
    if let Some(name) = choices
        .iter()
        .find(|name| fonts.iter().any(|font| font.as_str() == **name))
    {
        Font::set_font(Font::Helvetica, name);
    }
}

impl Ui {
    fn new(tx: mpsc::Sender<Action>, store: Store) -> Self {
        let device = store.device();
        let mut window = Window::new(100, 100, 900, 650, "pair").center_screen();
        window.set_color(BG);
        window.size_range(800, 600, 0, 0);
        let card_w = (window.w() - 2 * LANDING_INSET - CARD_GAP) / 2;
        let connect_x = (window.w() - (2 * card_w + CARD_GAP)) / 2;
        let host_x = connect_x + card_w + CARD_GAP;

        let landing = Group::new(0, 0, 900, 650, None);
        let mut menu = MenuBar::new(0, 0, 900, MENU_H, None);
        menu.add("File", Shortcut::None, fltk::menu::MenuFlag::Normal, |_| {});
        menu.add(
            "Connection",
            Shortcut::None,
            fltk::menu::MenuFlag::Normal,
            |_| {},
        );
        menu.add("Help", Shortcut::None, fltk::menu::MenuFlag::Normal, |_| {});
        menu.set_frame(FrameType::UpBox);
        menu.set_color(PANEL);
        heading(
            Frame::new(0, 72, 900, 38, None),
            "How do you want to pair?",
            22,
        );
        // These cards use the same width and a single centered gutter at the default size.
        let connect_card = panel(Group::new(connect_x, 135, card_w, 330, None));
        heading(
            Frame::new(connect_x + MARGIN, 150, card_w - 2 * MARGIN, 30, None),
            "Connect",
            19,
        );
        icon(
            Frame::new(connect_x + 60, 191, card_w - 120, 72, None),
            false,
        );
        let mut connect_description = Frame::new(
            connect_x + MARGIN,
            280,
            card_w - 2 * MARGIN,
            24,
            "Join another computer",
        );
        connect_description.set_align(Align::Center | Align::Inside);
        connect_description.set_label_color(Color::from_rgb(72, 72, 68));
        let mut open_connect = Button::new(connect_x + 52, 340, card_w - 104, 38, "Connect");
        button_style(&mut open_connect, true);
        connect_card.end();
        let host_card = panel(Group::new(host_x, 135, card_w, 330, None));
        heading(
            Frame::new(host_x + MARGIN, 150, card_w - 2 * MARGIN, 30, None),
            "Host",
            19,
        );
        icon(Frame::new(host_x + 60, 191, card_w - 120, 72, None), true);
        let mut host_description = Frame::new(
            host_x + MARGIN,
            280,
            card_w - 2 * MARGIN,
            24,
            "Share from this computer",
        );
        host_description.set_align(Align::Center | Align::Inside);
        host_description.set_label_color(Color::from_rgb(72, 72, 68));
        let mut open_host = Button::new(host_x + 52, 340, card_w - 104, 38, "Host");
        button_style(&mut open_host, true);
        host_card.end();
        let mut landing_status = recessed(Frame::new(0, 622, 900, STATUS_H, "●  Ready"));
        landing_status.set_label_color(GREEN);
        landing_status.set_align(Align::Left | Align::Inside);
        let mut wordmark = Frame::new(MARGIN, 586, 180, 24, "pair");
        wordmark.set_label_size(24);
        wordmark.set_align(Align::Left | Align::Inside);
        let mut version = Frame::new(750, 626, 132, 20, None);
        version.set_label(&format!("v{}", env!("CARGO_PKG_VERSION")));
        version.set_align(Align::Right | Align::Inside);
        landing.end();

        let mut host = Group::new(0, 0, 900, 650, None);
        heading(Frame::new(0, 35, 900, 45, None), "Host a note", 30);
        let mut host_name = Input::new(285, 105, 330, 36, "This computer  ");
        host_name.set_value(&device.name);
        field_style(&mut host_name);
        let mut save_name = Button::new(625, 105, 95, 36, "Save name");
        button_style(&mut save_name, false);
        let mut host_status = recessed(Frame::new(130, 165, 640, 55, "Starting host..."));
        host_status.set_align(Align::Center | Align::Inside | Align::Wrap);
        let mut host_phrase = recessed(Frame::new(120, 225, 660, 82, "Waiting for a computer..."));
        host_phrase.set_align(Align::Center | Align::Inside | Align::Wrap);
        host_phrase.set_label_size(15);
        let mut host_confirm = Button::new(265, 318, 240, 38, "Phrase Matches — Pair");
        button_style(&mut host_confirm, true);
        let mut host_reject = Button::new(515, 318, 105, 38, "Reject");
        button_style(&mut host_reject, false);
        let mut peers = Choice::new(285, 390, 300, 34, "Paired devices  ");
        field_style(&mut peers);
        let mut remove_peer = Button::new(595, 390, 125, 34, "Remove");
        button_style(&mut remove_peer, false);
        let mut toggle_host_advanced = Button::new(350, 440, 200, 32, "Connection help...");
        button_style(&mut toggle_host_advanced, false);
        let mut host_advanced = Group::new(250, 482, 450, 45, None);
        let mut host_port = Input::new(330, 488, 100, 32, "Port  ");
        host_port.set_value(PORT);
        field_style(&mut host_port);
        let mut reset = Button::new(450, 488, 145, 32, "Reset identity");
        button_style(&mut reset, false);
        host_advanced.end();
        host_advanced.hide();
        let mut host_back = Button::new(25, 585, 90, 38, "Stop");
        button_style(&mut host_back, false);
        host.end();
        host.hide();

        let mut connect = Group::new(0, 0, 900, 650, None);
        heading(Frame::new(0, 35, 900, 45, None), "Connect to a note", 30);
        let mut connect_name = Input::new(285, 82, 300, 30, "This computer  ");
        connect_name.set_value(&device.name);
        field_style(&mut connect_name);
        let mut save_connect_name = Button::new(595, 82, 95, 30, "Save name");
        button_style(&mut save_connect_name, false);
        let mut nearby = Choice::new(245, 125, 410, 38, "Nearby  ");
        field_style(&mut nearby);
        let mut connect_button = Button::new(380, 177, 180, 40, "Connect");
        button_style(&mut connect_button, true);
        let mut connect_status = recessed(Frame::new(
            120,
            220,
            660,
            56,
            "Searching for nearby computers...",
        ));
        connect_status.set_align(Align::Center | Align::Inside | Align::Wrap);
        let mut connect_phrase = recessed(Frame::new(
            120,
            280,
            660,
            82,
            "Select a computer to connect.",
        ));
        connect_phrase.set_align(Align::Center | Align::Inside | Align::Wrap);
        connect_phrase.set_label_size(15);
        let mut connect_confirm = Button::new(265, 372, 240, 38, "Phrase Matches — Pair");
        button_style(&mut connect_confirm, true);
        let mut connect_reject = Button::new(515, 372, 105, 38, "Reject");
        button_style(&mut connect_reject, false);
        let mut toggle_help = Button::new(325, 442, 250, 34, "Connection help...");
        button_style(&mut toggle_help, false);
        let mut help_group = Group::new(175, 485, 550, 105, None);
        let mut manual_ip = Input::new(225, 492, 205, 32, "IP  ");
        manual_ip.set_value("192.168.1.2");
        field_style(&mut manual_ip);
        let mut manual_port = Input::new(490, 492, 80, 32, "Port  ");
        manual_port.set_value(PORT);
        field_style(&mut manual_port);
        let mut manual_connect = Button::new(580, 492, 115, 32, "Connect");
        button_style(&mut manual_connect, true);
        let mut refresh = Button::new(225, 538, 105, 30, "Refresh");
        button_style(&mut refresh, false);
        let mut forget_host = Button::new(340, 538, 135, 30, "Forget host");
        button_style(&mut forget_host, false);
        let mut help = Frame::new(
            485,
            532,
            210,
            48,
            "Allow Pair on Private networks. On macOS, enable Local Network access.",
        );
        help.set_align(Align::Left | Align::Inside | Align::Wrap);
        help.set_label_size(11);
        help_group.end();
        help_group.hide();
        let mut connect_back = Button::new(25, 585, 90, 38, "Back");
        button_style(&mut connect_back, false);
        connect.end();
        connect.hide();

        let mut workspace = Group::new(0, 0, 900, 650, None);
        let mut workspace_title = Frame::new(16, 12, 220, 34, "Shared note");
        workspace_title.set_align(Align::Left | Align::Inside);
        workspace_title.set_label_size(20);
        let mut workspace_status = recessed(Frame::new(235, 12, 235, 34, "Connecting..."));
        workspace_status.set_align(Align::Left | Align::Inside | Align::Wrap);
        workspace_status.set_label_size(11);
        let mut take = Button::new(480, 12, 115, 34, "Take Control");
        button_style(&mut take, true);
        let mut copy = Button::new(603, 12, 82, 34, "Copy All");
        button_style(&mut copy, false);
        let mut draft = Button::new(693, 12, 100, 34, "Drafts (0)");
        button_style(&mut draft, false);
        let mut disconnect = Button::new(801, 12, 82, 34, "Disconnect");
        button_style(&mut disconnect, false);
        let area = Group::new(16, 56, 868, 535, None);
        let mut buffer = TextBuffer::default();
        buffer.set_tab_distance(4);
        let mut viewer = TextDisplay::new(16, 56, 868, 535, None);
        viewer.set_buffer(buffer.clone());
        viewer.set_text_font(Font::Helvetica);
        viewer.set_text_size(15);
        viewer.set_frame(FrameType::DownBox);
        viewer.set_color(FIELD);
        let mut editor = TextEditor::new(16, 56, 868, 535, None);
        editor.set_buffer(buffer.clone());
        editor.set_text_font(Font::Helvetica);
        editor.set_text_size(15);
        editor.set_frame(FrameType::DownBox);
        editor.set_color(FIELD);
        editor.set_tab_nav(false);
        editor.hide();
        area.end();
        let mut owner = recessed(Frame::new(16, 598, 868, 34, "●  Connecting..."));
        owner.set_align(Align::Left | Align::Inside);
        workspace.end();
        workspace.hide();
        window.end();
        window.resizable(&workspace);

        let suppress = Rc::new(Cell::new(false));
        buffer.add_modify_callback({
            let tx = tx.clone();
            let suppress = suppress.clone();
            move |_, i, d, _, _| {
                if !suppress.get() && (i != 0 || d != 0) {
                    let _ = tx.send(Action::Changed);
                }
            }
        });
        callback(&mut open_host, &tx, || Action::OpenHost);
        callback(&mut open_connect, &tx, || Action::OpenConnect);
        callback(&mut host_back, &tx, || Action::Back);
        callback(&mut connect_back, &tx, || Action::Back);
        callback(&mut connect_button, &tx, || Action::ConnectNearby);
        callback(&mut manual_connect, &tx, || Action::ConnectManual);
        callback(&mut refresh, &tx, || Action::Refresh);
        callback(&mut toggle_help, &tx, || Action::ToggleHelp);
        callback(&mut toggle_host_advanced, &tx, || {
            Action::ToggleHostAdvanced
        });
        callback(&mut save_name, &tx, || Action::SaveName);
        callback(&mut save_connect_name, &tx, || Action::SaveConnectName);
        callback(&mut remove_peer, &tx, || Action::RemovePeer);
        callback(&mut forget_host, &tx, || Action::ForgetHost);
        callback(&mut reset, &tx, || Action::ResetIdentity);
        callback(&mut host_confirm, &tx, || Action::ConfirmPairing);
        callback(&mut host_reject, &tx, || Action::RejectPairing);
        callback(&mut connect_confirm, &tx, || Action::ConfirmPairing);
        callback(&mut connect_reject, &tx, || Action::RejectPairing);
        callback(&mut take, &tx, || Action::TakeControl);
        callback(&mut copy, &tx, || Action::CopyAll);
        callback(&mut draft, &tx, || Action::Drafts);
        callback(&mut disconnect, &tx, || Action::Disconnect);
        window.set_callback({
            let tx = tx.clone();
            move |_| {
                let _ = tx.send(Action::Close);
            }
        });
        let mut ui = Self {
            window,
            landing,
            host,
            connect,
            workspace,
            screen: Screen::Landing,
            host_name,
            host_port,
            host_advanced,
            host_status,
            host_phrase,
            host_confirm,
            host_reject,
            peers,
            remove_peer,
            nearby,
            connect_name,
            connect_status,
            connect_phrase,
            connect_confirm,
            connect_reject,
            help_group,
            manual_ip,
            manual_port,
            workspace_title,
            workspace_status,
            owner,
            take,
            draft,
            editor,
            viewer,
            buffer,
            suppress,
            model: Editor::default(),
            network: None,
            discovery: None,
            discovered: Vec::new(),
            targets: Vec::new(),
            active_target_id: None,
            pairing: None,
            store,
            tx,
            timer_armed: false,
            last_change: Instant::now(),
            notice: String::new(),
            network_status: "Not connected.".into(),
        };
        ui.refresh_peers();
        ui
    }

    fn show(&mut self, screen: Screen) {
        self.screen = screen;
        self.landing.hide();
        self.host.hide();
        self.connect.hide();
        self.workspace.hide();
        match screen {
            Screen::Landing => self.landing.show(),
            Screen::Host => self.host.show(),
            Screen::Connect => self.connect.show(),
            Screen::Workspace => self.workspace.show(),
        }
        self.window.redraw();
    }
    fn refresh_peers(&mut self) {
        self.peers.clear();
        for peer in self.store.trusted_peers() {
            self.peers.add_choice(&peer.name);
        }
        if self.peers.size() > 0 {
            self.peers.set_value(0);
            self.remove_peer.activate();
        } else {
            self.peers.add_choice("No paired devices");
            self.peers.set_value(0);
            self.remove_peer.deactivate();
        }
    }
    fn parse_port(text: &str) -> Result<u16, String> {
        text.trim()
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| "Port must be from 1 to 65535.".into())
    }
    fn start_network(&mut self, mode: Mode, side: Side) -> Result<(), String> {
        if let Some(network) = &self.network {
            network.stop();
        }
        self.network = Some(
            Network::start(mode, app::awake).map_err(|_| "Could not start the network thread.")?,
        );
        self.model.start(side);
        self.network_status = "Starting...".into();
        Ok(())
    }
    fn start_host(&mut self) -> Result<(), String> {
        self.store.set_name(&self.host_name.value())?;
        let port = Self::parse_port(&self.host_port.value())?;
        self.start_network(
            Mode::Host {
                address: SocketAddr::from(([0, 0, 0, 0], port)),
                text: self.model.text.clone(),
                store: self.store.clone(),
            },
            Side::Host,
        )
    }
    fn connect_target(&mut self, target: ConnectTarget) -> Result<(), String> {
        self.active_target_id = target.id.clone();
        self.start_network(
            Mode::Connect {
                target,
                store: self.store.clone(),
            },
            Side::Peer,
        )
    }
    fn refresh_discovery(&mut self) {
        self.discovery = None;
        if self.screen == Screen::Connect && self.network.is_none() {
            self.network_status = "Searching nearby".into();
        }
        match DiscoveryBrowser::start(app::awake) {
            Ok(browser) => self.discovery = Some(browser),
            Err(error) => self.notice = error,
        }
    }

    fn discovery_update(&mut self) -> bool {
        let devices = self.discovery.as_mut().and_then(|browser| {
            browser
                .updates
                .has_changed()
                .unwrap_or(true)
                .then(|| browser.updates.borrow_and_update().clone())
        });
        let Some(devices) = devices else { return false };
        if devices == self.discovered {
            return false;
        }
        self.discovered = devices;
        self.targets.clear();
        self.nearby.clear();
        let trusted = self.store.trusted_host();
        for device in &self.discovered {
            let saved = trusted.as_ref().filter(|host| host.id == device.id);
            let addresses = ordered_addresses(
                saved.map(|host| host.address),
                device.addresses.iter().copied(),
            );
            self.targets.push(ConnectTarget {
                addresses: addresses.clone(),
                id: Some(device.id.clone()),
                name: Some(device.name.clone()),
                pairing: saved.map(|host| host.pairing.clone()),
            });
            self.nearby.add_choice(&format!(
                "{}{}",
                device.name,
                if saved.is_some() { "  —  Paired" } else { "" }
            ));
            if self.active_target_id.as_ref() == Some(&device.id)
                && let Some(network) = &self.network
            {
                let _ = network
                    .commands
                    .try_send(Command::UpdateAddresses(addresses));
            }
        }
        if let Some(host) = trusted
            && !self.discovered.iter().any(|device| device.id == host.id)
        {
            self.nearby
                .add_choice(&format!("{}  —  Paired (last address)", host.name));
            self.targets.push(ConnectTarget {
                addresses: vec![host.address],
                id: Some(host.id),
                name: Some(host.name),
                pairing: Some(host.pairing),
            });
        }
        if self.targets.is_empty() {
            self.nearby.add_choice("Searching...");
            self.nearby.deactivate();
        } else {
            self.nearby.activate();
            self.nearby.set_value(0);
            if self.network.is_none() {
                self.network_status = format!(
                    "Found {}",
                    self.targets[0].name.as_deref().unwrap_or("host")
                );
            }
        }
        true
    }
    fn schedule_flush(&mut self) {
        if !self.timer_armed && self.model.needs_flush() {
            self.timer_armed = true;
            let wait = DEBOUNCE.saturating_sub(self.last_change.elapsed());
            let tx = self.tx.clone();
            app::add_timeout3(wait.as_secs_f64().max(0.001), move |_| {
                let _ = tx.send(Action::Flush);
            });
        }
    }
    fn command(&mut self, command: Command) -> Result<(), String> {
        self.network
            .as_ref()
            .ok_or("Connect first.")?
            .commands
            .try_send(command)
            .map_err(|_| "Network is busy. Your local text is retained.".into())
    }

    fn act(&mut self, action: Action) -> Result<bool, String> {
        match action {
            Action::OpenHost => {
                self.show(Screen::Host);
                self.start_host()?;
            }
            Action::OpenConnect => {
                self.show(Screen::Connect);
                self.refresh_discovery();
            }
            Action::Back | Action::Disconnect => {
                if let Some(network) = &self.network {
                    network.stop();
                }
                self.network = None;
                self.discovery = None;
                self.active_target_id = None;
                self.model.connection(false, false);
                self.show(Screen::Landing);
            }
            Action::ConnectNearby => {
                let target = self
                    .targets
                    .get(self.nearby.value().max(0) as usize)
                    .cloned()
                    .ok_or("No nearby computer is selected.")?;
                self.connect_target(target)?;
            }
            Action::ConnectManual => {
                let ip: IpAddr = self
                    .manual_ip
                    .value()
                    .trim()
                    .parse()
                    .map_err(|_| "Enter a numeric IPv4 or IPv6 address.")?;
                if ip.is_unspecified() || ip.is_multicast() {
                    return Err("Enter the host computer's address.".into());
                }
                let address = SocketAddr::new(ip, Self::parse_port(&self.manual_port.value())?);
                let trusted = self.store.trusted_host();
                let pairing = trusted.as_ref().map(|host| host.pairing.clone());
                self.connect_target(ConnectTarget {
                    addresses: vec![address],
                    id: trusted.as_ref().map(|host| host.id.clone()),
                    name: trusted.as_ref().map(|host| host.name.clone()),
                    pairing,
                })?;
            }
            Action::Refresh => self.refresh_discovery(),
            Action::ToggleHelp => {
                if self.help_group.visible() {
                    self.help_group.hide()
                } else {
                    self.help_group.show()
                }
            }
            Action::ToggleHostAdvanced => {
                if self.host_advanced.visible() {
                    self.host_advanced.hide()
                } else {
                    self.host_advanced.show()
                }
            }
            Action::SaveName => {
                self.store.set_name(&self.host_name.value())?;
                self.notice = "Device name saved. Restart Host to advertise it.".into();
            }
            Action::SaveConnectName => {
                self.store.set_name(&self.connect_name.value())?;
                self.notice = "Device name saved.".into();
            }
            Action::RemovePeer => {
                let peers = self.store.trusted_peers();
                if let Some(peer) = peers.get(self.peers.value().max(0) as usize) {
                    self.store.forget_peer(&peer.id)?;
                    self.notice = format!("Removed {}.", peer.name);
                    self.refresh_peers();
                }
            }
            Action::ForgetHost => {
                if let Some(network) = &self.network {
                    network.stop();
                }
                self.network = None;
                self.model.connection(false, false);
                self.store.forget_host()?;
                self.notice = "Remembered host removed. Select it to pair again.".into();
                self.refresh_discovery();
            }
            Action::ResetIdentity => {
                if dialog::choice2_default(
                    "Reset the host certificate and remove every paired device?",
                    "Cancel",
                    "Reset",
                    "",
                ) == Some(1)
                {
                    if let Some(network) = &self.network {
                        network.stop();
                    }
                    self.network = None;
                    self.model.connection(false, false);
                    self.store.reset_host_identity()?;
                    self.refresh_peers();
                    self.notice = "Host identity reset.".into();
                    self.show(Screen::Landing);
                }
            }
            Action::Changed => {
                self.last_change = Instant::now();
                self.model
                    .set_text(self.buffer.text())
                    .map_err(str::to_string)?;
                self.schedule_flush();
            }
            Action::Flush => {
                self.timer_armed = false;
                if self.last_change.elapsed() >= DEBOUNCE
                    && let Some(edit) = self.model.prepare_edit()
                    && let Err(error) = self.command(Command::Edit(edit))
                {
                    self.model.enqueue_failed();
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
                        "Unsent edits or recovery drafts are in memory.",
                        "Keep open",
                        "Close",
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
            network
                .updates
                .has_changed()
                .unwrap_or(true)
                .then(|| network.updates.borrow_and_update().clone())
        });
        let Some(view) = view else { return false };
        let drafts = self.model.drafts.len();
        self.model.connection(view.connected, view.running);
        if let Some(snapshot) = view.snapshot {
            self.model.receive(snapshot, view.sync_serial);
        }
        self.pairing = view.pairing;
        if self.pairing.is_some() && self.screen == Screen::Workspace {
            self.show(if self.model.side == Side::Host {
                Screen::Host
            } else {
                Screen::Connect
            });
        }
        self.network_status = view.status;
        if self.model.drafts.len() > drafts {
            self.notice = "Unsent local text was kept in Drafts.".into();
        }
        if view.connected {
            self.discovery = None;
            self.show(Screen::Workspace);
        } else if view.running && self.model.side == Side::Peer && self.discovery.is_none() {
            self.refresh_discovery();
        }
        if !view.running {
            self.network = None;
            if self.screen == Screen::Connect {
                self.refresh_discovery();
            }
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
        if self.model.can_edit() {
            self.viewer.hide();
            self.editor.show();
        } else {
            self.editor.hide();
            self.viewer.show();
        }
        let phrase = self.pairing.as_ref().map_or_else(
            || "No phrase confirmation needed.".into(),
            |prompt| format!("UNVERIFIED — compare exactly:\n{}", prompt.phrase),
        );
        self.host_phrase.set_label(&phrase);
        self.connect_phrase.set_label(&phrase);
        let confirm = self
            .pairing
            .as_ref()
            .is_some_and(|prompt| !prompt.local_confirmed);
        if confirm {
            let label = if self.pairing.as_ref().is_some_and(|prompt| prompt.repairing) {
                "Repair Pairing"
            } else {
                "Phrase Matches — Pair"
            };
            self.host_confirm.set_label(label);
            self.connect_confirm.set_label(label);
            self.host_confirm.activate();
            self.connect_confirm.activate();
        } else {
            self.host_confirm.set_label("Phrase Matches — Pair");
            self.connect_confirm.set_label("Phrase Matches — Pair");
            self.host_confirm.deactivate();
            self.connect_confirm.deactivate();
        }
        if self.pairing.is_some() {
            self.host_reject.activate();
            self.connect_reject.activate();
        } else {
            self.host_reject.deactivate();
            self.connect_reject.deactivate();
        }
        let status = if self.notice.is_empty() {
            self.network_status.clone()
        } else {
            format!("{}  {}", self.notice, self.network_status)
        };
        self.host_status.set_label(&status);
        self.connect_status.set_label(&status);
        self.workspace_status.set_label(&status);
        let name = self
            .store
            .trusted_host()
            .map(|host| host.name)
            .unwrap_or_else(|| self.store.device().name);
        self.workspace_title
            .set_label(&format!("Shared with {name}"));
        let other = self
            .model
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.owner != self.model.side);
        if other && (self.model.side == Side::Host || self.model.connected) {
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
        let owner = if self.model.drafts.len() == MAX_DRAFTS {
            "Draft storage full."
        } else if self.model.can_edit() {
            if self.model.has_unsent() {
                "You have control · syncing..."
            } else {
                "You have control · saved at host"
            }
        } else {
            "Other computer has control · read only"
        };
        self.owner.set_label(&format!(
            "{}  {owner}",
            if self.model.connected { "●" } else { "○" }
        ));
        self.owner.set_label_color(if self.model.connected {
            GREEN
        } else {
            Color::from_rgb(65, 65, 62)
        });
    }

    fn show_drafts(&mut self) {
        if self.model.drafts.is_empty() {
            return;
        }
        let mut window = Window::new(120, 120, 690, 460, "pair — recovery drafts").center_screen();
        let mut select = Choice::new(12, 12, 666, 30, None);
        for (i, text) in self.model.drafts.iter().enumerate() {
            select.add_choice(&format!("Draft {} ({} bytes)", i + 1, text.len()));
        }
        select.set_value((self.model.drafts.len() - 1) as i32);
        let mut buffer = TextBuffer::default();
        buffer.set_text(&self.model.drafts[select.value() as usize]);
        let mut display = TextDisplay::new(12, 52, 666, 340, None);
        display.set_buffer(buffer.clone());
        display.set_text_font(Font::Helvetica);
        let mut copy = Button::new(12, 410, 120, 32, "Copy Draft");
        let mut restore = Button::new(142, 410, 120, 32, "Restore");
        let mut discard = Button::new(272, 410, 120, 32, "Discard");
        let mut close = Button::new(558, 410, 120, 32, "Close");
        window.end();
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
        match result.get() {
            1 => {
                if let Err(error) = self.model.restore_draft(selection.get()) {
                    self.notice = error.into()
                } else {
                    self.last_change = Instant::now();
                    self.schedule_flush();
                }
            }
            2 => {
                self.model.drafts.remove(selection.get());
            }
            _ => {}
        }
        app::delete_widget(window);
    }
}

pub fn run() {
    let application = app::App::default()
        .with_scheme(app::Scheme::Base)
        .load_system_fonts();
    choose_font();
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
