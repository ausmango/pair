use std::{
    cell::Cell,
    net::{IpAddr, SocketAddr},
    rc::Rc,
    sync::mpsc,
    time::{Duration, Instant},
};

use fltk::{
    app,
    browser::{BrowserScrollbar, HoldBrowser},
    button::Button,
    dialog, draw,
    enums::{Align, Color, ColorDepth, Damage, Event, Font, FrameType, Key, Shortcut},
    frame::Frame,
    group::Group,
    image::RgbImage,
    input::Input,
    menu::Choice,
    prelude::*,
    text::{TextBuffer, TextDisplay, TextEditor},
    window::Window,
};
use pair::{
    discovery::{
        ConnectionFlow, DeviceConnectionState, DiscoveredDevice, DiscoveryBrowser, ProbeRequest,
        probe_addresses,
    },
    editor::{Editor, MAX_DRAFTS},
    network::{
        Command, ConnectTarget, ConnectionProgress, Mode, Network, PairingPrompt, ordered_addresses,
    },
    persistence::Store,
    state::Side,
};

const DEBOUNCE: Duration = Duration::from_millis(20);
const PORT: &str = "47321";
const BG: Color = Color::from_rgb(238, 237, 231);
const PANEL: Color = Color::from_rgb(212, 211, 205);
const FIELD: Color = Color::from_rgb(248, 247, 242);
const GREEN: Color = Color::from_rgb(36, 122, 69);
const MARGIN: i32 = 16;
const ROW: i32 = 32;
const GAP: i32 = 8;
const STATUS_H: i32 = 24;
const CONTENT_W: i32 = 640;
const LIST_H: i32 = 176;
const SELECTED: Color = Color::from_rgb(230, 240, 223);
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
    BeginProbe(ProbeRequest),
    ProbeComplete {
        id: String,
        generation: u64,
        reachable: bool,
    },
    CancelAttempt,
    ConnectManual,
    Refresh,
    RefreshHost,
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
    peers: HoldBrowser,
    remove_peer: Button,
    nearby: HoldBrowser,
    connect_button: Button,
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
    connection_flow: ConnectionFlow,
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
    button.super_draw(false);
    button.set_frame(FrameType::UpBox);
    button.set_color(PANEL);
    button.set_label_font(if primary {
        Font::HelveticaBold
    } else {
        Font::Helvetica
    });
    button.set_align(Align::Center | Align::Inside | Align::Clip);
    button.set_label_color(Color::Black);
    button.set_selection_color(GREEN);
    button.set_label_size(14);
    let hover = Rc::new(Cell::new(false));
    let hover_event = hover.clone();
    button.handle(move |button, event| {
        match event {
            Event::Enter => hover_event.set(true),
            Event::Leave => hover_event.set(false),
            _ => return false,
        }
        button.redraw();
        // Native FLTK still owns clicks, keyboard activation and focus.
        false
    });
    button.draw(move |b| {
        let active = b.active_r();
        let pressed = b.value();
        let (top, bottom) = if !active {
            (PANEL, PANEL)
        } else if pressed {
            (
                Color::from_rgb(168, 186, 192),
                Color::from_rgb(206, 219, 223),
            )
        } else if hover.get() {
            (
                Color::from_rgb(235, 246, 251),
                Color::from_rgb(185, 209, 219),
            )
        } else {
            (Color::from_rgb(240, 239, 233), PANEL)
        };
        let (x, y, w, h) = (b.x(), b.y(), b.w(), b.h());
        gradient(x, y, w, h, top, bottom);
        draw::draw_box(
            if pressed {
                FrameType::DownFrame
            } else {
                FrameType::UpFrame
            },
            x,
            y,
            w,
            h,
            PANEL,
        );
        draw::draw_rect_with_color(
            x,
            y,
            w,
            h,
            if b.has_focus() && active {
                Color::from_rgb(100, 131, 141)
            } else if primary && active {
                GREEN
            } else {
                Color::from_rgb(105, 108, 105)
            },
        );
        let offset = i32::from(pressed);
        draw::push_clip(x + 4, y + 3, w - 8, h - 6);
        draw::set_font(b.label_font(), b.label_size());
        draw::set_draw_color(if active {
            Color::Black
        } else {
            Color::from_rgb(125, 125, 121)
        });
        draw::draw_text2(&b.label(), x + offset, y + offset, w, h, Align::Center);
        draw::pop_clip();
    });
}

fn gradient(x: i32, y: i32, w: i32, h: i32, top: Color, bottom: Color) {
    let (r1, g1, b1) = top.to_rgb();
    let (r2, g2, b2) = bottom.to_rgb();
    for row in 0..h {
        let mix = |a: u8, b: u8| {
            (i32::from(a) + (i32::from(b) - i32::from(a)) * row / (h - 1).max(1)) as u8
        };
        draw::set_draw_color(Color::from_rgb(mix(r1, r2), mix(g1, g2), mix(b1, b2)));
        draw::draw_line(x, y + row, x + w - 1, y + row);
    }
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
    group.super_draw(false);
    group.set_frame(FrameType::EngravedBox);
    group.set_color(PANEL);
    group.draw(|g| {
        // Child-only damage must not erase the unchanged siblings.
        if g.damage_type() == Damage::Child {
            g.draw_children();
            return;
        }
        let (x, y, w, h) = (g.x(), g.y(), g.w(), g.h());
        draw::draw_rbox(x, y, w, h, 6, true, Color::from_rgb(128, 131, 127));
        draw::draw_rbox(x + 1, y + 1, w - 2, h - 2, 5, true, Color::White);
        draw::draw_rbox(x + 2, y + 2, w - 4, h - 4, 4, true, PANEL);
        gradient(
            x + 6,
            y + 2,
            w - 12,
            h - 4,
            Color::from_rgb(237, 237, 232),
            PANEL,
        );
        g.draw_children();
    });
    group
}
fn heading(mut frame: Frame, text: &str, size: i32) {
    frame.set_label(text);
    frame.set_label_size(size);
    frame.set_align(Align::Center | Align::Inside | Align::Clip);
}
fn icon(mut frame: Frame, host: bool) {
    frame.super_draw(false);
    let pixels: &[u8] = if host {
        include_bytes!("../assets/host-icon.rgba")
    } else {
        include_bytes!("../assets/connect-icon.rgba")
    };
    let mut image = RgbImage::new(pixels, 96, 96, ColorDepth::Rgba8)
        .expect("embedded role icon must contain 96x96 RGBA pixels");
    frame.draw(move |f| {
        draw::push_clip(f.x(), f.y(), f.w(), f.h());
        image.draw(f.x() + (f.w() - 96) / 2, f.y() + (f.h() - 96) / 2, 96, 96);
        draw::pop_clip();
    });
}

fn ellipsis(text: &str, width: i32) -> String {
    let clean: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if draw::width(&clean) <= f64::from(width) {
        return clean;
    }
    let mut short = clean;
    while !short.is_empty() && draw::width(&format!("{short}…")) > f64::from(width) {
        short.pop();
    }
    format!("{short}…")
}

fn computer_list(browser: &mut HoldBrowser, host: bool) {
    browser.set_color(BG);
    browser.set_selection_color(SELECTED);
    browser.set_has_scrollbar(BrowserScrollbar::VerticalAlways);
    browser.set_scrollbar_size(16);
    let hovered_y = Rc::new(Cell::new(None));
    let events = hovered_y.clone();
    browser.handle(move |b, event| {
        match event {
            Event::Move | Event::Enter => events.set(Some(app::event_y())),
            Event::Leave => events.set(None),
            _ => return false,
        }
        b.redraw();
        false
    });
    // Native browser retains selection, scrolling and keyboard interaction.
    // Only the interior is overpainted; the scrollbar and recessed frame stay native.
    browser.draw(move |b| {
        let (x, y, w, h) = (b.x() + 2, b.y() + 2, b.w() - 20, b.h() - 4);
        draw::push_clip(x, y, w, h);
        draw::set_draw_color(BG);
        draw::draw_rectf(x, y, w, h);
        draw::set_font(Font::Helvetica, 13);
        let row_h = draw::height().max(24);
        if b.size() == 0 {
            draw::set_draw_color(Color::Black);
            let empty_y = y + (h - 64).max(0) / 2;
            draw::draw_text2("Looking for computers", x, empty_y, w, 24, Align::Center);
            draw::set_font(Font::Helvetica, 12);
            draw::set_draw_color(Color::from_rgb(85, 85, 80));
            draw::draw_text2(
                if host {
                    "Open Pair on another computer and choose Connect."
                } else {
                    "Open Pair on another computer and choose Host."
                },
                x + 8,
                empty_y + 28,
                w - 16,
                32,
                Align::Center | Align::Wrap,
            );
        } else {
            for line in 1..=b.size() {
                let row_y = y + (line - 1) * row_h - b.position();
                if row_y + row_h <= y || row_y >= y + h {
                    continue;
                }
                let selected = b.value() == line;
                let hovered = hovered_y
                    .get()
                    .is_some_and(|my| my >= row_y && my < row_y + row_h);
                draw::set_draw_color(if selected {
                    SELECTED
                } else if hovered {
                    Color::from_rgb(225, 234, 237)
                } else {
                    BG
                });
                draw::draw_rectf(x, row_y, w, row_h);
                if selected {
                    draw::draw_rect_with_color(x, row_y, w, row_h, GREEN);
                }
                let text = b.text(line).unwrap_or_default();
                let (name, state) = text.rsplit_once('\t').unwrap_or((&text, "Offline"));
                let online = matches!(state, "Ready to pair" | "Ready to connect" | "Connected");
                draw::set_draw_color(if online {
                    GREEN
                } else {
                    Color::from_rgb(151, 153, 148)
                });
                draw::draw_pie(x + 8, row_y + (row_h - 6) / 2, 6, 6, 0., 360.);
                draw::set_draw_color(Color::Black);
                draw::draw_text2(
                    &ellipsis(name, w - 144),
                    x + 24,
                    row_y,
                    w - 144,
                    row_h,
                    Align::Left,
                );
                draw::set_draw_color(if online {
                    GREEN
                } else {
                    Color::from_rgb(85, 85, 80)
                });
                draw::draw_text2(state, x + w - 112, row_y, 104, row_h, Align::Left);
            }
        }
        draw::pop_clip();
    });
}

fn row_icons(browser: &mut HoldBrowser) {
    for line in 1..=browser.size() {
        if browser.icon(line).is_none() {
            browser.set_icon(
                line,
                Some(
                    RgbImage::new(&[0; 88], 1, 22, ColorDepth::Rgba8)
                        .expect("fixed transparent row spacer"),
                ),
            );
        }
    }
}

fn computer_row(name: &str, state: &str) -> String {
    let name: String = name
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    format!("{name}\t{state}")
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

// Keep labels inside their allocated rectangles, including remote device names.
fn bound_labels(group: &mut Group) {
    for i in 0..group.children() {
        if let Some(mut child) = group.child(i) {
            if child.align().contains(Align::Inside) {
                child.set_align(child.align() | Align::Clip);
            }
            if let Some(mut nested) = child.as_group() {
                bound_labels(&mut nested);
            }
        }
    }
}

fn place(group: &Group, index: i32, x: i32, y: i32, w: i32, h: i32) {
    if let Some(mut child) = group.child(index) {
        child.resize(x, y, w, h);
    }
}

fn footer(mut frame: Frame) {
    frame.super_draw(false);
    let mut pixels = include_bytes!("../assets/pear-icon.rgba").to_vec();
    for pixel in pixels.chunks_exact_mut(4) {
        pixel[3] = (u16::from(pixel[3]) * 55 / 100) as u8;
    }
    let mut pear = RgbImage::new(&pixels, 24, 24, ColorDepth::Rgba8)
        .expect("embedded Pair logo must contain 24x24 RGBA pixels");
    pear.scale(20, 20, true, true);
    frame.draw(move |f| {
        draw::set_draw_color(BG);
        draw::draw_rectf(f.x(), f.y(), f.w(), f.h());
        pear.draw(f.x() + MARGIN + 30, f.y() + 1, 20, 20);
        draw::set_draw_color(Color::from_rgb(130, 130, 124));
        draw::set_font(Font::HelveticaBold, 13);
        draw::draw_text2("pair", f.x() + MARGIN, f.y() - 2, 32, f.h(), Align::Left);
        draw::set_draw_color(Color::from_rgb(130, 130, 124));
        draw::draw_text2(
            concat!("v", env!("CARGO_PKG_VERSION")),
            f.x() + f.w() - 110,
            f.y() - 2,
            94,
            f.h(),
            Align::Right,
        );
    });
}

fn layout_screens(screens: &mut [Group; 4], w: i32, h: i32) {
    for screen in screens.iter_mut() {
        screen.resize(0, 0, w, h);
        place(screen, screen.children() - 1, 0, h - STATUS_H, w, STATUS_H);
    }
    let landing = &screens[0];
    let card_w = (CONTENT_W.min(w - 2 * MARGIN) - GAP) / 2;
    let left = (w - 2 * card_w - GAP) / 2;
    let top = ((h - STATUS_H - 320) / 2).clamp(24, 72);
    place(landing, 0, MARGIN, MARGIN, w - 2 * MARGIN, 24);
    place(landing, 1, left, top, 2 * card_w + GAP, ROW);
    for (index, x) in [(2, left), (3, left + card_w + GAP)] {
        place(landing, index, x, top + ROW + GAP, card_w, 248);
        if let Some(card) = landing.child(index).and_then(|c| c.as_group()) {
            if let Some(mut title) = card.child(0) {
                title.show();
            }
            place(&card, 0, x + MARGIN, top + 48, card_w - 2 * MARGIN, ROW);
            place(&card, 1, x + (card_w - 96) / 2, top + 88, 96, 96);
            place(&card, 2, x + MARGIN, top + 192, card_w - 2 * MARGIN, 24);
            place(&card, 3, x + MARGIN, top + 232, card_w - 2 * MARGIN, 32);
        }
    }
    if let Some(mut ready) = landing.child(4) {
        ready.hide();
    }
    // Branding lives in the shared bottom bar now.
    for index in [5, 6] {
        if let Some(mut child) = landing.child(index) {
            child.hide();
        }
    }
    let width = CONTENT_W.min(w - 2 * MARGIN);
    let x = (w - width) / 2;
    for (screen, is_host) in [(&screens[1], true), (&screens[2], false)] {
        let (list, status, phrase, confirm, reject) = if is_host {
            (7, 3, 4, 5, 6)
        } else {
            (3, 5, 6, 7, 8)
        };
        let help_open = screen.child(10).is_some_and(|c| c.visible());
        let pairing_open = screen.child(phrase).is_some_and(|c| c.visible());
        let extra = if help_open {
            if is_host { 64 } else { 96 }
        } else {
            0
        } + if pairing_open { 104 } else { 0 };
        let action_y = (112 + LIST_H + GAP + extra).min(h - STATUS_H - GAP - ROW);
        let status_y = action_y;
        place(screen, 0, x, 12, width, ROW);
        place(screen, 1, x + 112, 52, width - 212, ROW);
        place(screen, 2, x + width - 92, 52, 92, ROW);
        place(screen, 11, x, action_y, 80, ROW);
        place(screen, 9, x + 88, action_y, 160, ROW);
        place(
            screen,
            if is_host { 8 } else { 4 },
            x + width - 120,
            action_y,
            120,
            ROW,
        );
        if let Some(mut status) = screen.child(status) {
            status.hide();
        }
        let mut list_bottom = status_y - GAP;
        if let Some(mut help) = screen.child(10).and_then(|c| c.as_group()) {
            let help_h = if is_host { 56 } else { 88 };
            let help_y = list_bottom - help_h;
            help.resize(x, help_y, width, help_h);
            help.set_frame(FrameType::EngravedBox);
            if is_host {
                place(&help, 0, x + 60, help_y + 12, 100, ROW);
                place(&help, 1, x + 180, help_y + 12, 145, ROW);
            } else {
                place(&help, 0, x + 34, help_y + 6, width - 380, ROW);
                place(&help, 1, x + width - 296, help_y + 6, 100, ROW);
                place(&help, 2, x + width - 186, help_y + 6, 170, ROW);
                place(&help, 3, x + 16, help_y + 46, 100, ROW);
                place(&help, 4, x + 124, help_y + 46, 120, ROW);
                place(&help, 5, x + 258, help_y + 40, width - 274, 40);
            }
            if help_open {
                list_bottom = help_y - GAP;
            }
        }
        if pairing_open {
            let phrase_y = list_bottom - 96;
            place(screen, phrase, x, phrase_y, width, 52);
            place(screen, confirm, x + width - 338, phrase_y + 60, 240, ROW);
            place(screen, reject, x + width - 90, phrase_y + 60, 90, ROW);
            list_bottom = phrase_y - GAP;
        }
        let list_h = (list_bottom - 112).min(LIST_H);
        place(screen, list, x, 112, width, list_h);
        let empty = screen
            .child(list)
            .and_then(|c| HoldBrowser::from_dyn_widget(&c))
            .is_some_and(|b| b.size() == 0);
        let centered_search = empty;
        place(
            screen,
            12,
            if centered_search {
                x + (width - 120) / 2
            } else {
                x + width - 256
            },
            action_y,
            120,
            ROW,
        );
        if let Some(mut list_widget) = screen.child(list) {
            list_widget.set_align(Align::TopLeft);
        }
    }
    let workspace = &screens[3];
    place(workspace, 0, MARGIN, GAP, w - 464, ROW);
    for (i, offset, width) in [(2, 438, 120), (3, 308, 84), (4, 214, 94), (5, 110, 94)] {
        place(workspace, i, w - offset, GAP, width, ROW);
    }
    place(workspace, 7, MARGIN, 48, w - 2 * MARGIN, 24);
    let editor_h = h - STATUS_H - 90;
    place(workspace, 6, MARGIN, 82, w - 2 * MARGIN, editor_h);
    if let Some(area) = workspace.child(6).and_then(|c| c.as_group()) {
        for i in 0..2 {
            place(&area, i, MARGIN, 82, w - 2 * MARGIN, editor_h);
        }
    }
    if let Some(mut status) = workspace.child(1) {
        status.hide();
    }
    for screen in screens {
        screen.redraw();
    }
}

impl Ui {
    fn new(tx: mpsc::Sender<Action>, store: Store) -> Self {
        let device = store.device();
        let mut window = Window::new(100, 100, 760, 500, "pair").center_screen();
        window.set_color(BG);
        window.size_range(760, 500, 0, 0);
        let card_w = (window.w() - 2 * LANDING_INSET - CARD_GAP) / 2;
        let connect_x = (window.w() - (2 * card_w + CARD_GAP)) / 2;
        let host_x = connect_x + card_w + CARD_GAP;

        let landing = Group::new(0, 0, 900, 650, None);
        heading(Frame::new(0, 0, 900, 24, None), "", 14);
        heading(
            Frame::new(0, 72, 900, 38, None),
            "How do you want to pair?",
            18,
        );
        // These cards use the same width and a single centered gutter at the default size.
        let connect_card = panel(Group::new(connect_x, 135, card_w, 330, None));
        heading(
            Frame::new(connect_x + MARGIN, 150, card_w - 2 * MARGIN, 30, None),
            "Connect",
            16,
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
        connect_description.set_label_size(12);
        let mut open_connect = Button::new(connect_x + 52, 340, card_w - 104, 38, "Connect");
        button_style(&mut open_connect, true);
        connect_card.end();
        let host_card = panel(Group::new(host_x, 135, card_w, 330, None));
        heading(
            Frame::new(host_x + MARGIN, 150, card_w - 2 * MARGIN, 30, None),
            "Host",
            16,
        );
        icon(Frame::new(host_x + 60, 191, card_w - 120, 72, None), true);
        let mut host_description = Frame::new(
            host_x + MARGIN,
            280,
            card_w - 2 * MARGIN,
            24,
            "Share this note",
        );
        host_description.set_align(Align::Center | Align::Inside);
        host_description.set_label_color(Color::from_rgb(72, 72, 68));
        host_description.set_label_size(12);
        let mut open_host = Button::new(host_x + 52, 340, card_w - 104, 38, "Host");
        button_style(&mut open_host, true);
        host_card.end();
        let mut landing_status = recessed(Frame::new(0, 622, 900, STATUS_H, "Ready"));
        landing_status.set_label_color(Color::from_rgb(65, 65, 62));
        landing_status.set_align(Align::Left | Align::Inside);
        let mut wordmark = Frame::new(MARGIN, 586, 180, 24, "pair");
        wordmark.set_label_size(24);
        wordmark.set_align(Align::Left | Align::Inside);
        let mut version = Frame::new(750, 626, 132, 20, None);
        version.set_label(&format!("v{}", env!("CARGO_PKG_VERSION")));
        version.set_align(Align::Right | Align::Inside);
        landing.end();

        let mut host = Group::new(0, 0, 900, 650, None);
        host.set_frame(FrameType::ThinUpBox);
        host.set_color(BG);
        heading(Frame::new(0, 35, 900, 45, None), "Host a note", 18);
        let mut host_name = Input::new(285, 105, 330, 36, "This computer  ");
        host_name.set_value(&device.name);
        field_style(&mut host_name);
        let mut save_name = Button::new(625, 105, 95, 36, "Save name");
        button_style(&mut save_name, false);
        let mut host_status = recessed(Frame::new(130, 165, 640, 55, "Starting host..."));
        host_status.set_align(Align::Center | Align::Inside | Align::Wrap);
        let mut host_phrase = recessed(Frame::new(120, 225, 660, 82, "Waiting for a computer..."));
        host_phrase.set_align(Align::Center | Align::Inside | Align::Wrap);
        host_phrase.set_label_size(12);
        host_status.set_label_size(12);
        host_status.set_align(Align::Left | Align::Inside | Align::Clip);
        let mut host_confirm = Button::new(265, 318, 240, 38, "Phrase Matches — Pair");
        button_style(&mut host_confirm, true);
        let mut host_reject = Button::new(515, 318, 105, 38, "Reject");
        button_style(&mut host_reject, false);
        let mut peers = HoldBrowser::new(285, 390, 300, 34, "Computers");
        peers.set_text_size(13);
        peers.set_format_char('\x01');
        field_style(&mut peers);
        computer_list(&mut peers, true);
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
        let mut host_search = Button::new(0, 0, 120, ROW, "Search again");
        button_style(&mut host_search, false);
        callback(&mut host_search, &tx, || Action::RefreshHost);
        host.end();
        host.hide();

        let mut connect = Group::new(0, 0, 900, 650, None);
        connect.set_frame(FrameType::ThinUpBox);
        connect.set_color(BG);
        heading(Frame::new(0, 35, 900, 45, None), "Connect to a note", 18);
        let mut connect_name = Input::new(285, 82, 300, 30, "This computer  ");
        connect_name.set_value(&device.name);
        field_style(&mut connect_name);
        let mut save_connect_name = Button::new(595, 82, 95, 30, "Save name");
        button_style(&mut save_connect_name, false);
        let mut nearby = HoldBrowser::new(245, 125, 410, 38, "Computers");
        nearby.set_text_size(13);
        nearby.set_tooltip("Select a computer, then choose Connect.");
        computer_list(&mut nearby, false);
        nearby.set_format_char('\x01');
        field_style(&mut nearby);
        let mut connect_button = Button::new(380, 177, 180, 40, "Connect");
        button_style(&mut connect_button, true);
        connect_button.set_shortcut(Shortcut::from_key(Key::Enter));
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
        connect_phrase.set_label_size(12);
        connect_status.set_label_size(12);
        connect_status.set_align(Align::Left | Align::Inside | Align::Clip);
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
        let mut connect_search = Button::new(0, 0, 120, ROW, "Search again");
        button_style(&mut connect_search, false);
        callback(&mut connect_search, &tx, || Action::Refresh);
        connect.end();
        connect.hide();

        let mut workspace = Group::new(0, 0, 900, 650, None);
        let mut workspace_title = Frame::new(16, 12, 220, 34, "Shared note");
        workspace_title.set_align(Align::Left | Align::Inside);
        workspace_title.set_label_size(13);
        let mut workspace_status = recessed(Frame::new(235, 12, 235, 34, "Connecting..."));
        workspace_status.set_align(Align::Left | Align::Inside | Align::Wrap);
        workspace_status.set_label_size(12);
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
        owner.set_label_size(12);
        workspace.end();
        workspace.hide();
        window.end();
        // Own the geometry: only the editor grows vertically, never toolbar rows.
        window.resizable(&workspace);
        let mut screens = [
            landing.clone(),
            host.clone(),
            connect.clone(),
            workspace.clone(),
        ];
        for screen in screens.iter_mut() {
            screen.begin();
            footer(Frame::new(0, 622, 900, STATUS_H, None));
            screen.end();
            bound_labels(screen);
        }
        layout_screens(&mut screens, window.w(), window.h());
        window.resize_callback(move |_, _, _, w, h| {
            layout_screens(&mut screens, w, h);
        });

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
        let escape = tx.clone();
        window.handle(move |_, event| {
            if event == Event::KeyDown && app::event_key() == Key::Escape {
                let _ = escape.send(Action::CancelAttempt);
                true
            } else {
                false
            }
        });
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
            connect_button,
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
            connection_flow: ConnectionFlow::default(),
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
        ui.update_dialog_layout();
        ui
    }

    fn update_dialog_layout(&mut self) {
        let show_pairing = self.pairing.is_some();
        for mut widget in [
            self.host_phrase.as_base_widget(),
            self.host_confirm.as_base_widget(),
            self.host_reject.as_base_widget(),
            self.connect_phrase.as_base_widget(),
            self.connect_confirm.as_base_widget(),
            self.connect_reject.as_base_widget(),
        ] {
            if show_pairing {
                widget.show();
            } else {
                widget.hide();
            }
        }
        let mut screens = [
            self.landing.clone(),
            self.host.clone(),
            self.connect.clone(),
            self.workspace.clone(),
        ];
        layout_screens(&mut screens, self.window.w(), self.window.h());
        self.window.redraw();
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
            self.peers.add(&format!("{}\tOffline", peer.name));
        }
        if self.peers.size() > 0 {
            self.peers.select(1);
            self.remove_peer.activate();
            self.remove_peer.show();
        } else {
            self.remove_peer.deactivate();
            self.remove_peer.hide();
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
        self.network_status = if side == Side::Peer {
            "Establishing secure connection…".into()
        } else {
            "Starting...".into()
        };
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
        if self.screen == Screen::Connect
            && self.network.is_none()
            && self.active_target_id.is_none()
        {
            self.network_status = "Searching nearby".into();
        }
        match DiscoveryBrowser::start(app::awake) {
            Ok(browser) => self.discovery = Some(browser),
            Err(error) => self.notice = error,
        }
    }

    fn elapsed_label(at: Option<Instant>) -> String {
        let Some(at) = at else {
            return "unknown".into();
        };
        let elapsed = at.elapsed();
        if elapsed < Duration::from_secs(5) {
            "just now".into()
        } else if elapsed < Duration::from_secs(60) {
            format!("{}s ago", elapsed.as_secs())
        } else {
            format!("{}m ago", elapsed.as_secs() / 60)
        }
    }

    fn refresh_nearby_list(&mut self) {
        let trusted = self.store.trusted_host();
        if let Some(host) = trusted.as_ref()
            && self.connection_flow.device(&host.id).is_none()
        {
            self.connection_flow.remember_offline(DiscoveredDevice {
                id: host.id.clone(),
                name: host.name.clone(),
                addresses: vec![host.address],
            });
        }
        let devices: Vec<_> = self.connection_flow.devices().cloned().collect();
        self.targets.clear();
        self.nearby.clear();
        for known in devices {
            let saved = trusted.as_ref().filter(|host| host.id == known.device.id);
            self.targets.push(ConnectTarget {
                addresses: ordered_addresses(
                    saved.map(|host| host.address),
                    known.device.addresses.iter().copied(),
                ),
                id: Some(known.device.id.clone()),
                name: Some(known.device.name.clone()),
                pairing: saved.map(|host| host.pairing.clone()),
            });
            let state = if known.state == DeviceConnectionState::Offline {
                format!(
                    "Offline · last seen {}",
                    Self::elapsed_label(known.last_seen)
                )
            } else {
                known.state.label().into()
            };
            self.nearby.add(&computer_row(&known.device.name, &state));
        }
        if self.targets.is_empty() {
            self.nearby.deactivate();
        } else {
            self.nearby.activate();
            if self.nearby.value() <= 0 {
                self.nearby.select(1);
            }
        }
    }

    fn queue_probe(&self, request: ProbeRequest) {
        let _ = self.tx.send(Action::BeginProbe(request));
    }

    fn device_details(&self, id: &str) -> String {
        let Some(device) = self.connection_flow.device(id) else {
            return "No safe connection details are available.".into();
        };
        let mut details = vec![
            format!("Device: {}", device.device.name),
            format!("Discovery: {}", device.state.label()),
            format!(
                "Discovered addresses: {}",
                if device.last_seen.is_some() {
                    device.device.addresses.len()
                } else {
                    0
                }
            ),
            format!("Pairing: {}", if device.paired { "Paired" } else { "New" }),
            format!("Last seen: {}", Self::elapsed_label(device.last_seen)),
        ];
        if let Some(connected) = device.last_connected {
            details.push(format!(
                "Last successful connection: {}",
                Self::elapsed_label(Some(connected))
            ));
        }
        if let Some(method) = &device.last_method {
            details.push(format!("Last successful method: {method}"));
        }
        if let Some(failure) = &device.failure {
            details.push(format!("Last result: {failure}"));
        }
        details.join("\n")
    }

    fn prompt_for_device(&mut self, id: &str) -> Result<(), String> {
        let device = self
            .connection_flow
            .device(id)
            .cloned()
            .ok_or("The selected computer is no longer available.")?;
        let target = self
            .targets
            .iter()
            .find(|target| target.id.as_deref() == Some(id))
            .cloned()
            .ok_or("The selected computer is no longer available.")?;
        self.connection_flow.mark_prompted(id);
        let (message, primary) = if device.paired {
            (
                format!(
                    "Reconnect to {}?\n\nLast verified device found nearby.",
                    device.device.name
                ),
                "Reconnect",
            )
        } else {
            (
                format!(
                    "{} found\n\n{} is visible nearby.\nConnect from {}?",
                    device.device.name,
                    device.device.name,
                    self.store.device().name
                ),
                "Connect",
            )
        };
        loop {
            match dialog::choice2_default(&message, primary, "Not now", "Details") {
                Some(0) => {
                    self.connection_flow.mark_connecting(id);
                    self.network_status = "Establishing secure connection…".into();
                    self.connect_target(target)?;
                    return Ok(());
                }
                Some(2) => dialog::message_default(&self.device_details(id)),
                _ => {
                    self.connection_flow.not_now(id);
                    return Ok(());
                }
            }
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
        let trusted = self.store.trusted_host();
        let probes = self.connection_flow.observe(
            &devices,
            trusted.as_ref().map(|host| host.id.as_str()),
            Instant::now(),
        );
        self.discovered = devices;
        for device in &self.discovered {
            if self.active_target_id.as_ref() == Some(&device.id)
                && let Some(network) = &self.network
            {
                let saved = trusted.as_ref().filter(|host| host.id == device.id);
                let addresses = ordered_addresses(
                    saved.map(|host| host.address),
                    device.addresses.iter().copied(),
                );
                let _ = network
                    .commands
                    .try_send(Command::UpdateAddresses(addresses));
            }
        }
        self.refresh_nearby_list();
        if self.network.is_none() && !self.targets.is_empty() {
            self.network_status = "Found just now".into();
        }
        for probe in probes {
            self.queue_probe(probe);
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
                if self.network.is_some() {
                    return Ok(false);
                }
                let id = self
                    .targets
                    .get((self.nearby.value() - 1).max(0) as usize)
                    .and_then(|target| target.id.clone())
                    .ok_or("No nearby computer is selected.")?;
                match self.connection_flow.device(&id).map(|device| device.state) {
                    Some(DeviceConnectionState::ReadyToPair)
                    | Some(DeviceConnectionState::ReadyToConnect) => {
                        self.prompt_for_device(&id)?;
                    }
                    Some(DeviceConnectionState::FoundButUnreachable)
                    | Some(DeviceConnectionState::Offline) => {
                        if let Some(probe) = self.connection_flow.retry(&id) {
                            self.network_status = "Checking connection…".into();
                            self.queue_probe(probe);
                        }
                    }
                    Some(DeviceConnectionState::FoundJustNow)
                    | Some(DeviceConnectionState::CheckingReachability) => {
                        self.network_status = "Checking connection…".into();
                    }
                    _ => {}
                }
                self.refresh_nearby_list();
            }
            Action::BeginProbe(request) => {
                if self.connection_flow.begin_probe(&request) {
                    self.network_status = "Checking connection…".into();
                    self.refresh_nearby_list();
                    let tx = self.tx.clone();
                    std::thread::spawn(move || {
                        let reachable = probe_addresses(&request.addresses);
                        let _ = tx.send(Action::ProbeComplete {
                            id: request.id,
                            generation: request.generation,
                            reachable,
                        });
                        app::awake();
                    });
                }
            }
            Action::ProbeComplete {
                id,
                generation,
                reachable,
            } => {
                if self
                    .connection_flow
                    .finish_probe(&id, generation, reachable)
                {
                    self.network_status = if reachable {
                        self.connection_flow
                            .device(&id)
                            .map(|device| device.state.label())
                            .unwrap_or("Found just now")
                            .into()
                    } else {
                        "Found but unreachable".into()
                    };
                    self.refresh_nearby_list();
                    if reachable && self.connection_flow.should_prompt(&id) {
                        self.prompt_for_device(&id)?;
                    }
                }
            }
            Action::CancelAttempt => {
                if self.screen == Screen::Connect {
                    if let Some(network) = &self.network {
                        network.stop();
                    }
                    self.network = None;
                    let cancelled = self.active_target_id.take().or_else(|| {
                        self.targets
                            .get((self.nearby.value() - 1).max(0) as usize)
                            .and_then(|target| target.id.clone())
                    });
                    if let Some(id) = cancelled {
                        self.connection_flow.not_now(&id);
                    }
                    self.model.connection(false, false);
                    self.network_status = "Searching nearby".into();
                    self.refresh_nearby_list();
                }
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
            Action::RefreshHost => {
                self.refresh_peers();
                self.notice = "Listening for connections".into();
            }
            Action::ToggleHelp => {
                if self.help_group.visible() {
                    self.help_group.hide()
                } else {
                    self.help_group.show()
                }
                self.update_dialog_layout();
            }
            Action::ToggleHostAdvanced => {
                if self.host_advanced.visible() {
                    self.host_advanced.hide()
                } else {
                    self.host_advanced.show()
                }
                self.update_dialog_layout();
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
                if let Some(peer) = peers.get((self.peers.value() - 1).max(0) as usize) {
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
        let failure = view
            .diagnostic
            .as_ref()
            .map(|diagnostic| diagnostic.summary.clone());
        self.network_status = if self.pairing.is_some() {
            "Waiting for phrase confirmation".into()
        } else if view.status.contains("Retrying") {
            "Retrying…".into()
        } else if let Some(diagnostic) = &view.diagnostic {
            diagnostic.summary.clone()
        } else {
            match view.progress.as_ref() {
                Some(ConnectionProgress::SearchingNearby) => "Searching nearby".into(),
                Some(ConnectionProgress::FoundDevice(name)) => format!("Found {name}"),
                Some(ConnectionProgress::TryingLocalNetwork)
                | Some(ConnectionProgress::TryingDirectEthernet) => "Checking connection…".into(),
                Some(ConnectionProgress::EstablishingSecureConnection)
                | Some(ConnectionProgress::Authenticating) => {
                    "Establishing secure connection…".into()
                }
                Some(ConnectionProgress::ConnectedSecurely) => "Connected".into(),
                None if view.running && !view.connected => "Retrying…".into(),
                None => "Connection ended".into(),
            }
        };
        if self.model.drafts.len() > drafts {
            self.notice = "Unsent local text was kept in Drafts.".into();
        }
        if view.connected {
            if let Some(id) = self.active_target_id.as_deref() {
                let method = self.store.trusted_host().map_or("Local network", |host| {
                    if matches!(host.address.ip(), IpAddr::V4(ip) if ip.is_link_local()) {
                        "Direct Ethernet"
                    } else {
                        "Local network"
                    }
                });
                self.connection_flow
                    .mark_connected(id, Instant::now(), method);
            }
            self.discovery = None;
            self.show(Screen::Workspace);
        } else if view.running && self.model.side == Side::Peer && self.discovery.is_none() {
            self.refresh_discovery();
        }
        if !view.running {
            if let Some(id) = self.active_target_id.as_deref() {
                self.connection_flow.mark_failure(
                    id,
                    failure.unwrap_or_else(|| "Connection attempt failed".into()),
                );
            }
            self.network = None;
            if self.screen == Screen::Connect {
                self.refresh_discovery();
            }
        }
        self.schedule_flush();
        true
    }

    fn present_computers(&mut self) {
        for (index, target) in self.targets.iter().enumerate() {
            let active = target
                .id
                .as_ref()
                .is_some_and(|id| Some(id) == self.active_target_id.as_ref());
            let state = if active && self.pairing.as_ref().is_some_and(|p| p.repairing) {
                "Pairing requires repair".into()
            } else if active && self.model.connected {
                "Connected".into()
            } else if let Some(known) = target
                .id
                .as_deref()
                .and_then(|id| self.connection_flow.device(id))
            {
                if known.state == DeviceConnectionState::Offline {
                    format!(
                        "Offline · last seen {}",
                        Self::elapsed_label(known.last_seen)
                    )
                } else {
                    known.state.label().into()
                }
            } else {
                "Offline · last seen unknown".into()
            };
            let line = index as i32 + 1;
            let text = computer_row(target.name.as_deref().unwrap_or("Computer"), &state);
            if self.nearby.text(line).as_deref() != Some(&text) {
                self.nearby.set_text(line, &text);
            }
        }
        for (index, peer) in self.store.trusted_peers().iter().enumerate() {
            let prompt = self.pairing.as_ref().filter(|p| p.other_name == peer.name);
            let state = if prompt.is_some_and(|p| p.repairing) {
                "Needs repair"
            } else if prompt.is_some() && self.model.connected {
                "Connected"
            } else {
                "Offline"
            };
            let line = index as i32 + 1;
            let text = computer_row(&peer.name, state);
            if self.peers.text(line).as_deref() != Some(&text) {
                self.peers.set_text(line, &text);
            }
        }
        row_icons(&mut self.peers);
        row_icons(&mut self.nearby);
        let selected = self
            .targets
            .get((self.nearby.value() - 1).max(0) as usize)
            .and_then(|target| target.id.as_deref())
            .and_then(|id| self.connection_flow.device(id));
        let (label, enabled) = if self.network.is_some() {
            ("Connecting…", false)
        } else {
            match selected.map(|device| device.state) {
                Some(DeviceConnectionState::ReadyToPair) => ("Connect", true),
                Some(DeviceConnectionState::ReadyToConnect) => ("Reconnect", true),
                Some(DeviceConnectionState::FoundButUnreachable)
                | Some(DeviceConnectionState::Offline) => ("Retry", true),
                Some(DeviceConnectionState::FoundJustNow)
                | Some(DeviceConnectionState::CheckingReachability) => ("Checking…", false),
                _ => ("Connect", false),
            }
        };
        self.connect_button.set_label(label);
        if enabled {
            self.connect_button.activate();
        } else {
            self.connect_button.deactivate();
        }
        if self.screen != Screen::Workspace {
            self.update_dialog_layout();
        }
    }

    fn render(&mut self) {
        self.present_computers();
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
        if self.host_phrase.visible() != self.pairing.is_some() {
            self.update_dialog_layout();
        }
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
        self.host_status.set_tooltip(&status);
        self.connect_status.set_tooltip(&status);
        self.workspace_status.set_label(&status);
        self.workspace_status.set_tooltip(&status);
        let name = self
            .store
            .trusted_host()
            .map(|host| host.name)
            .unwrap_or_else(|| self.store.device().name);
        self.workspace_title
            .set_label(&format!("Shared with {name}"));
        self.workspace_title
            .set_tooltip(&format!("Shared with {name}"));
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
