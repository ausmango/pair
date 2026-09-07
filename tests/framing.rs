use std::io;

use pair::{
    protocol::{
        MAX_FRAME_BYTES, MAX_HELLO_BYTES, MAX_NOTE_BYTES, Message, read_frame, validate_note,
        write_frame,
    },
    state::Authority,
};
use tokio::io::{AsyncWriteExt, duplex};

#[tokio::test]
async fn partial_reads_and_consecutive_frames_preserve_exact_text() {
    let text = "#!/bin/sh\r\n\t  echo '梨 🍐 café Ελληνικά'\n\n  end\r\n";
    let snapshot = Authority::new(text.into()).unwrap().snapshot;
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &Message::State { snapshot })
        .await
        .unwrap();
    write_frame(&mut bytes, &Message::TakeControl {})
        .await
        .unwrap();
    let (mut tx, mut rx) = duplex(7);
    let task = tokio::spawn(async move {
        for byte in bytes {
            tx.write_all(&[byte]).await.unwrap();
        }
    });
    let Message::State { snapshot } = read_frame(&mut rx, MAX_FRAME_BYTES).await.unwrap() else {
        panic!("expected state")
    };
    assert_eq!(snapshot.text, text);
    assert!(matches!(
        read_frame(&mut rx, MAX_FRAME_BYTES).await.unwrap(),
        Message::TakeControl {}
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn impossible_lengths_are_rejected_before_reading_or_allocating_body() {
    for length in [0, (MAX_FRAME_BYTES + 1) as u32, u32::MAX] {
        let bytes = length.to_be_bytes();
        let mut input = bytes.as_slice();
        assert_eq!(
            read_frame(&mut input, MAX_FRAME_BYTES)
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
    let bytes = (MAX_HELLO_BYTES as u32 + 1).to_be_bytes();
    assert_eq!(
        read_frame(&mut bytes.as_slice(), MAX_HELLO_BYTES)
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn truncated_headers_and_bodies_are_not_treated_as_complete_messages() {
    for input in [vec![0, 0], vec![0, 0, 0, 10, b'{', b'}']] {
        assert_eq!(
            read_frame(&mut input.as_slice(), MAX_FRAME_BYTES)
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}

#[tokio::test]
async fn malformed_utf8_json_unknown_fields_and_wrong_types_fail_without_echoing_input() {
    for body in [
        vec![0xff, 0xfe],
        b"{secret-note-invalid-json".to_vec(),
        br#"{"type":"take_control","extra":"secret-note"}"#.to_vec(),
        br#"{"type":"unknown"}"#.to_vec(),
        br#"{"type":"hello","version":"secret-note","token":"bad"}"#.to_vec(),
    ] {
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend(body);
        let error = read_frame(&mut frame.as_slice(), MAX_FRAME_BYTES)
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!error.to_string().contains("secret-note"));
    }
}

#[tokio::test]
async fn maximum_escaped_note_fits_but_oversized_notes_and_nul_do_not() {
    let text = "\u{1}".repeat(MAX_NOTE_BYTES);
    let snapshot = Authority::new(text.clone()).unwrap().snapshot;
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &Message::State { snapshot })
        .await
        .unwrap();
    assert!(bytes.len() <= MAX_FRAME_BYTES + 4);
    let Message::State { snapshot } = read_frame(&mut bytes.as_slice(), MAX_FRAME_BYTES)
        .await
        .unwrap()
    else {
        panic!("expected state")
    };
    assert_eq!(snapshot.text, text);
    assert!(validate_note(&"a".repeat(MAX_NOTE_BYTES + 1)).is_err());
    assert!(validate_note("a\0b").is_err());
    assert!(validate_note(&"梨".repeat(MAX_NOTE_BYTES / 3 + 1)).is_err());
}
