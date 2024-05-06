package src.server;

public enum MessageType {
    SUCCESS(""), ERROR("ERROR: "), INFO("SERVER: ");

    public final String prefix;

    MessageType(String prefix) {
        this.prefix = prefix;
    }

}
