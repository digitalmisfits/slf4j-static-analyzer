package javagrep.system;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static java.lang.String.format;

public class Console {

    public static Optional<Integer> getTerminalWidth() {

        List<String> command = Arrays.asList("/bin/bash", "-c", "tput cols 2> /dev/tty");

        Process process;
        try {
            ProcessBuilder processBuilder = new ProcessBuilder().redirectErrorStream(true);
            process = processBuilder
                    .command(command)
                    .start();
            process.waitFor();
        } catch (IOException | InterruptedException e) {
            throw new IllegalStateException("Failed to execute process", e);
        }

        String output = getStdOut(process).trim();

        if (process.exitValue() > 0) {
            return Optional.empty();
        }

        try {
            return Optional.of(Integer.parseInt(output));
        } catch (NumberFormatException e) {
            System.err.println("Failed to convert process output to integer, defaulting to 80 columns");
        }

        return Optional.empty();
    }

    private static String getStdOut(final Process process) {
        try {
            return IOUtils.toString(process.getInputStream(), "UTF-8");
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not read process output (input stream)", e);
        }
    }


    public static class Colors {

        public static final String RESET = "\033[0m";

        public static final String BLACK = "\033[0;30m";
        public static final String RED = "\033[0;31m";
        public static final String GREEN = "\033[0;32m";
        public static final String YELLOW = "\033[0;33m";
        public static final String BLUE = "\033[0;34m";
        public static final String PURPLE = "\033[0;35m";
        public static final String CYAN = "\033[0;36m";
        public static final String WHITE = "\033[0;37m";

        public static final String BLACK_BOLD = "\033[1;30m";
        public static final String RED_BOLD = "\033[1;31m";
        public static final String GREEN_BOLD = "\033[1;32m";
        public static final String YELLOW_BOLD = "\033[1;33m";
        public static final String BLUE_BOLD = "\033[1;34m";
        public static final String PURPLE_BOLD = "\033[1;35m";
        public static final String CYAN_BOLD = "\033[1;36m";
        public static final String WHITE_BOLD = "\033[1;37m";

        public static final String BLACK_UNDERLINED = "\033[4;30m";
        public static final String RED_UNDERLINED = "\033[4;31m";
        public static final String GREEN_UNDERLINED = "\033[4;32m";
        public static final String YELLOW_UNDERLINED = "\033[4;33m";
        public static final String BLUE_UNDERLINED = "\033[4;34m";
        public static final String PURPLE_UNDERLINED = "\033[4;35m";
        public static final String CYAN_UNDERLINED = "\033[4;36m";
        public static final String WHITE_UNDERLINED = "\033[4;37m";

        public static final String BLACK_BACKGROUND = "\033[40m";
        public static final String RED_BACKGROUND = "\033[41m";
        public static final String GREEN_BACKGROUND = "\033[42m";
        public static final String YELLOW_BACKGROUND = "\033[43m";
        public static final String BLUE_BACKGROUND = "\033[44m";
        public static final String PURPLE_BACKGROUND = "\033[45m";
        public static final String CYAN_BACKGROUND = "\033[46m";
        public static final String WHITE_BACKGROUND = "\033[47m";

        public static final String BLACK_BRIGHT = "\033[0;90m";
        public static final String RED_BRIGHT = "\033[0;91m";
        public static final String GREEN_BRIGHT = "\033[0;92m";
        public static final String YELLOW_BRIGHT = "\033[0;93m";
        public static final String BLUE_BRIGHT = "\033[0;94m";
        public static final String PURPLE_BRIGHT = "\033[0;95m";
        public static final String CYAN_BRIGHT = "\033[0;96m";
        public static final String WHITE_BRIGHT = "\033[0;97m";

        public static final String BLACK_BOLD_BRIGHT = "\033[1;90m";
        public static final String RED_BOLD_BRIGHT = "\033[1;91m";
        public static final String GREEN_BOLD_BRIGHT = "\033[1;92m";
        public static final String YELLOW_BOLD_BRIGHT = "\033[1;93m";
        public static final String BLUE_BOLD_BRIGHT = "\033[1;94m";
        public static final String PURPLE_BOLD_BRIGHT = "\033[1;95m";
        public static final String CYAN_BOLD_BRIGHT = "\033[1;96m";
        public static final String WHITE_BOLD_BRIGHT = "\033[1;97m";

        public static final String BLACK_BACKGROUND_BRIGHT = "\033[0;100m";
        public static final String RED_BACKGROUND_BRIGHT = "\033[0;101m";
        public static final String GREEN_BACKGROUND_BRIGHT = "\033[0;102m";
        public static final String YELLOW_BACKGROUND_BRIGHT = "\033[0;103m";
        public static final String BLUE_BACKGROUND_BRIGHT = "\033[0;104m";
        public static final String PURPLE_BACKGROUND_BRIGHT = "\033[0;105m";
        public static final String CYAN_BACKGROUND_BRIGHT = "\033[0;106m";
        public static final String WHITE_BACKGROUND_BRIGHT = "\033[0;107m";
    }
}
