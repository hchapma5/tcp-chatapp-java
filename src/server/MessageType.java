package src.server;

/**
 * The MessageType enum represents different types of messages that can be sent
 * by the server.
 * Each message type has a corresponding prefix that can be used to format the
 * message.
 */
public enum MessageType {
    SUCCESS(""), ERROR("ERROR: "), INFO("SERVER: ");

    public final String prefix;

    /**
     * Constructs a MessageType with the specified prefix.
     *
     * @param prefix the prefix associated with the message type
     */
    MessageType(String prefix) {
        this.prefix = prefix;
    }
}
