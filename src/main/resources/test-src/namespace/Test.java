package namespace;

public class Test {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Test.class);

    public static void main(String... args) {

        log.info("Test", new Test.InnerClass().getClass(), 1, true "Hello", Boolean.FALSE);
    }

    public static class InnerClass {

        @Override
        public String toString() {
            return "InnerClass{}";
        }
    }
}