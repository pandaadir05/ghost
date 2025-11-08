// Event handling module for future expansion
// Currently events are handled in main.rs but this provides structure for complex event handling

use crossterm::event::{Event, KeyEvent, MouseEvent};

#[derive(Debug, Clone)]
pub enum AppEvent {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Tick,
    Quit,
    Refresh,
    ClearDetections,
    ClearLogs,
}

impl From<Event> for AppEvent {
    fn from(event: Event) -> Self {
        match event {
            Event::Key(key) => AppEvent::Key(key),
            Event::Mouse(mouse) => AppEvent::Mouse(mouse),
            _ => AppEvent::Tick,
        }
    }
}

pub struct EventHandler {
    // Future: Add event queue, rate limiting, etc.
}

impl EventHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for EventHandler {
    fn default() -> Self {
        Self::new()
    }
}