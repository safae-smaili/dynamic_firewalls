import java.util.Objects;

public class PortRange implements Comparable<PortRange> {
    int start, end;

    PortRange(String start, String end) {
        this.start = Integer.parseInt(start);
        this.end = Integer.parseInt(end);
    }
    //addition
    public boolean contains(int port) {
    	return port>=start && port <= end;
    }
    //end

    @Override
    public int compareTo(PortRange p) {
        return Integer.compare(this.start, p.start); // only compares start values
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PortRange portRange = (PortRange) o;
        return start == portRange.start;
    }

    @Override
    public int hashCode() {
        return Objects.hash(start);
    }
    @Override
    public String toString() {
        if (start == end) {
            return String.valueOf(start);
        } else {
            return start + "-" + end;
        }
    }
}

