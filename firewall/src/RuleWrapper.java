import java.util.Objects;

public class RuleWrapper {
    String direction;
    String protocol;
    Rule rule;

    public RuleWrapper(String direction, String protocol, Rule rule) {
        this.direction = direction;
        this.protocol = protocol;
        this.rule = rule;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RuleWrapper)) return false;
        RuleWrapper that = (RuleWrapper) o;
        return direction.equals(that.direction) &&
               protocol.equals(that.protocol) &&
               rule.equals(that.rule);
    }

    @Override
    public int hashCode() {
        return Objects.hash(direction, protocol, rule);
    }

}

