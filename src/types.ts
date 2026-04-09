export interface Keystroke {
  timestamp: number;
  key: string;
  type: "keydown" | "keyup";
}

export interface PasteEvent {
  timestamp: number;
  contentLength: number;
  content: string;
}

export interface WritingSession {
  id: string;
  userId: string;
  title: string;
  content: string;
  createdAt: number;
  updatedAt: number;
  keystrokes: Keystroke[];
  pastes: PasteEvent[];
  metrics: {
    wpm: number;
    accuracy: number;
    totalKeystrokes: number;
    totalPastes: number;
    duration: number; // in seconds
  };
}

export interface UserProfile {
  uid: string;
  email: string;
  displayName: string;
  photoURL?: string;
  createdAt: number;
}
