package javagrep;


import de.vandermeer.asciitable.AsciiTable;
import de.vandermeer.asciitable.CWC_FixedWidth;
import de.vandermeer.skb.interfaces.transformers.textformat.TextAlignment;
import io.vavr.collection.Array;
import io.vavr.collection.List;
import io.vavr.collection.Stream;
import io.vavr.control.Either;
import io.vavr.control.Option;
import javagrep.system.Console;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;
import org.eclipse.jdt.core.JavaCore;
import org.eclipse.jdt.core.dom.*;
import org.slf4j.Logger;
import org.slf4j.Marker;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

import static java.lang.String.format;
import static java.lang.String.join;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static javagrep.Main.Slf4jLoggerMethodInvocationVisitor.Predicates.*;
import static javagrep.system.Console.Colors.RED;
import static javagrep.system.Console.Colors.RESET;
import static org.apache.commons.io.FileUtils.readFileToString;
import static org.eclipse.jdt.core.JavaCore.setComplianceOptions;

public class Main {

    private static AtomicInteger counter = new AtomicInteger(0);

    public
    static void main(String[] args) throws IOException {

        ArgumentParser parser = ArgumentParsers.newFor("javagrep").build()
                .defaultHelp(true)
                .description("Find dangerous slf4j log statements");
        parser.addArgument("-cp", "--classpath")
                .required(true)
                .dest("classpath")
                .help("Path to cp.txt in \"mvn dependency:build-classpath -Dmdep.outputFile=cp.txt]\"");
        parser.addArgument("sources")
                .nargs("+")
                .help("full path to the de-lombok'd java sources (usually \"/path/to/project/target/generated-sources/delombok/main/java\" ");

        Namespace ns = null;
        try {
            ns = parser.parseArgs(args);
        } catch (ArgumentParserException e) {
            parser.handleError(e);
            System.exit(1);
        }

        System.out.println("Using classpath " + ns.getString("classpath"));
        System.out.println("Using sources " + ns.getString("sources"));

        String[] classpath = readFileToString(
                new File(ns.getString("classpath")), UTF_8).split(":");

        String[] sources = ns.getList("sources").stream()
                .map(o -> Paths.get((String) o))
                .flatMap(p -> {
                            try {
                                return Files.walk(p)
                                        .filter(Files::isRegularFile)
                                        .filter(path -> path.getFileName().toString().endsWith(".java"))
                                        .map(path -> path.toAbsolutePath().toString());
                            } catch (IOException e) {
                                throw new RuntimeException("Failed to read sources from " + p);
                            }
                        }
                ).toArray(String[]::new);

        java.util.List<SourceAndCompilationUnit> compilationUnits = List.<SourceAndCompilationUnit>empty().asJavaMutable();

        parseAST(sources, classpath, new FileASTRequestor() {
            @Override
            public void acceptAST(String sourceFilePath, CompilationUnit ast) {

                final String source;
                try {
                    source = readFileToString(Paths.get(sourceFilePath).toFile(), UTF_8);
                } catch (IOException e) {
                    throw new RuntimeException(format("Failed to read %s with charset %s", sourceFilePath, UTF_8));
                }

                Path pathToSource = Paths.get(sourceFilePath);
                compilationUnits.add(new SourceAndCompilationUnit(pathToSource, source, ast));
            }

            @Override
            public void acceptBinding(String bindingKey, IBinding binding) {
                super.acceptBinding(bindingKey, binding);
            }
        });

        compilationUnits.forEach(sourceAndCompilationUnit ->
                sourceAndCompilationUnit.cu.accept(new Slf4jLoggerMethodInvocationVisitor(sourceAndCompilationUnit)));

        if (counter.get() > 0) {
            System.exit(1);
        }
    }

    static class Slf4jLoggerMethodInvocationVisitor extends ASTVisitor {

        private final SourceAndCompilationUnit sourceAndCompilationUnit;

        Slf4jLoggerMethodInvocationVisitor(final SourceAndCompilationUnit sourceAndCompilationUnit) {
            this.sourceAndCompilationUnit = sourceAndCompilationUnit;
        }

        @Override
        public void endVisit(MethodInvocation node) {

            IMethodBinding iMethodBinding = node.resolveMethodBinding();

            if (iMethodBinding != null) {
                if (equalsType(bind(iMethodBinding.getDeclaringClass()), Logger.class.getName())) {

                    String methodName = iMethodBinding.getName();
                    if (List.of("error", "warn", "info").contains(methodName.toLowerCase())) {

                        Stream<Expression> rejected = asExpression((node.arguments()))
                                .flatMap(Slf4jLoggerMethodInvocationVisitor::expandTernary)
                                .reject(expression -> {
                                    Predicate<Expression> allowedTypeDeclaration =
                                            isLogMarker
                                                    .or(isPrimitive)
                                                    .or(isEnum)
                                                    .or(isAllowedLiteral)
                                                    .or(isAllowedPackage)
                                                    .or(isAllowedSuperClass)
                                                    .or(isAllowedJavaLangClass)
                                                    .or(isAllowedJavaUtilClass)
                                                    .or(isAllowedJavaUtilCollection)
                                                    .or(isThrowable);

                                    return allowedTypeDeclaration.and(isAllowedToString).test(expression);
                                });

                        if (rejected.isEmpty()) {
                            return;
                        }

                        String statement = sourceAndCompilationUnit.source.substring(node.getStartPosition(),
                                node.getStartPosition() + node.getLength() + 1);
                        int lineNumber = sourceAndCompilationUnit.cu.getLineNumber(node.getStartPosition());
                        List<String> rejectedArguments = rejected
                                .map(e -> e.toString() + "<" + Option.of(e.resolveTypeBinding()).map(ITypeBinding::getQualifiedName).getOrElse("unresolved") + ">")
                                .collect(List.collector());

                        int terminalWidth = Console.getTerminalWidth().orElse(100);

                        System.out.println(RED + counter.incrementAndGet() + ": " + sourceAndCompilationUnit.pathToSource.toString() + RESET);
                        AsciiTable at = new AsciiTable();
                        at.addRule();
                        at.addRow("Linenumber", lineNumber);
                        at.addRule();
                        at.addRow("Statement", statement);
                        at.addRule();
                        at.addRow("Rejected", join("<br />", rejectedArguments));
                        at.addRule();
                        at.setTextAlignment(TextAlignment.LEFT);

                        at.getContext().setFrameBottomMargin(1);
                        at.getRenderer().setCWC(new CWC_FixedWidth().add(12).add(88));
                        System.out.println(at.render(terminalWidth));
                    }
                }
            }
        }

        static class Predicates {

            static final Predicate<Expression> isPrimitive
                    = e -> getType(bind(e)).map(ITypeBinding::isPrimitive).getOrElse(false);

            static final Predicate<Expression> isEnum
                    = e -> getType(bind(e)).map(ITypeBinding::isEnum).getOrElse(false);

            static final Predicate<ITypeBinding> isEnumBinding
                    = ITypeBinding::isEnum;

            static final Predicate<Expression> isThrowable
                    = e -> isThrowable(bind(e));

            static final Predicate<Expression> isLogMarker
                    = e -> equalsType(bind(e),
                    Marker.class.getName());

            static final Predicate<Expression> isAllowedLiteral
                    = e -> e instanceof StringLiteral
                    || e instanceof NumberLiteral
                    || e instanceof BooleanLiteral;

            static boolean isAllowedPackageInternal(final Either<ITypeBinding, Expression> expressionOrBinding) {
                return isAllowedPackage(expressionOrBinding,
                        "java.time");
            }

            static boolean isAllowedSuperclassInternal(final Either<ITypeBinding, Expression> expressionOrBinding) {
                return equalsSuperClass(expressionOrBinding,
                        Number.class.getName());
            }

            static boolean isAllowedJavaLangClassInternal(final Either<ITypeBinding, Expression> expressionOrBinding) {
                boolean equalsConcreteType = equalsType(expressionOrBinding,
                        Character.class.getName(),
                        String.class.getName(),
                        Boolean.class.getName(),
                        Class.class.getName());
                boolean equalsTypeClass = equalsParameterizedType(expressionOrBinding, Class.class.getName());
                return equalsConcreteType || equalsTypeClass;
            }

            static boolean isAllowedJavaUtilClassInternal(final Either<ITypeBinding, Expression> expressionOrBinding) {
                return equalsType(expressionOrBinding,
                        UUID.class.getName(),
                        Currency.class.getName(),
                        Locale.class.getName(),
                        Date.class.getName(),
                        "net.logstash.logback.marker.LogstashMarker");
            }

            static final Predicate<Expression> isAllowedPackage
                    = e -> isAllowedPackageInternal(bind(e));

            static final Predicate<ITypeBinding> isAllowedPackageBinding
                    = b -> isAllowedPackageInternal(bind(b));

            static final Predicate<Expression> isAllowedSuperClass
                    = e -> isAllowedSuperclassInternal(bind(e));

            static final Predicate<ITypeBinding> isAllowedSuperClassBinding
                    = e -> isAllowedSuperclassInternal(bind(e));

            static final Predicate<Expression> isAllowedJavaLangClass
                    = e -> isAllowedJavaLangClassInternal(bind(e));

            static final Predicate<ITypeBinding> isAllowedJavaLangClassBinding
                    = b -> isAllowedJavaLangClassInternal(bind(b));

            static final Predicate<Expression> isAllowedJavaUtilClass
                    = e -> isAllowedJavaUtilClassInternal(bind(e));

            static final Predicate<ITypeBinding> isAllowedJavaUtilClassBinding
                    = e -> isAllowedJavaUtilClassInternal(bind(e));

            static final Predicate<Expression> isAllowedJavaUtilCollection
                    = Slf4jLoggerMethodInvocationVisitor::isAllowedIfJavaUtilCollection;

            static final Predicate<Expression> isAllowedToString
                    = Slf4jLoggerMethodInvocationVisitor::isAllowedIfToString;
        }

        static boolean isAllowedPackage(final Either<ITypeBinding, Expression> expressionOrBinding, final String... packageNames) {
            return getType(expressionOrBinding)
                    .flatMap(b -> Option.of(b.getPackage()))
                    .exists(p -> Array.of(packageNames).contains(p.getName()));
        }

        static boolean isAllowedIfJavaUtilCollection(final Expression expression) {
            return findSuperType(bind(expression), Collection.class.getName())
                    .fold(
                            () -> false,
                            binding -> Stream.of(binding.getTypeArguments()).forAll(
                                    isAllowedJavaLangClassBinding
                                            .or(isAllowedJavaUtilClassBinding)
                                            .or(isAllowedSuperClassBinding)
                                            .or(isEnumBinding)));
        }

        static boolean isAllowedIfToString(final Expression expression) {
            if (expression instanceof MethodInvocation) {
                IMethodBinding methodBinding = ((MethodInvocation) expression).resolveMethodBinding();
                if ("toString".equalsIgnoreCase(methodBinding.getName())) {
                    return isAllowedPackageBinding.or(isAllowedJavaUtilClassBinding)
                            .test(methodBinding.getDeclaringClass());
                }
            }

            return true; // if its not a method invocation, pass
        }

        static List<ITypeBinding> resolveAllSuperTypes(final ITypeBinding binding) {
            List<ITypeBinding> superTypes = cons(binding.getSuperclass(), asList(binding.getInterfaces()));

            if (superTypes.isEmpty()) {
                return List.empty();
            }

            return cons(binding, superTypes.flatMap(Slf4jLoggerMethodInvocationVisitor::resolveAllSuperTypes));
        }

        static Option<ITypeBinding> findSuperType(final Either<ITypeBinding, Expression> expressionOrBinding,
                                                  final String qualifiedName) {
            return getType(expressionOrBinding)
                    .flatMap(b -> resolveAllSuperTypes(b)
                            .find(superType -> equalsType(bind(superType.getTypeDeclaration()), qualifiedName)));
        }

        static boolean isThrowable(final Either<ITypeBinding, Expression> expressionOrBinding) {
            return equalsType(expressionOrBinding, Throwable.class.getName())
                    || equalsSuperType(expressionOrBinding, Throwable.class.getName());
        }

        static boolean equalsType(final Either<ITypeBinding, Expression> expressionOrBinding,
                                  final String... qualifiedTypeNames) {
            return getType(expressionOrBinding)
                    .exists(b -> Stream.of(qualifiedTypeNames)
                            .filter(Objects::nonNull)
                            .exists(name -> name.equalsIgnoreCase(b.getQualifiedName())));
        }

        static boolean equalsParameterizedType(final Either<ITypeBinding, Expression> expressionOrBinding,
                                               final String... qualifiedTypeNames) {
            return getType(expressionOrBinding)
                    .exists(b -> Stream.of(qualifiedTypeNames)
                            .exists(name -> b.isParameterizedType() && b.getTypeDeclaration().getQualifiedName().equalsIgnoreCase(name)));
        }

        static boolean equalsSuperClass(final Either<ITypeBinding, Expression> expressionOrBinding,
                                        final String... qualifiedTypeNames) {
            return getType(expressionOrBinding)
                    .flatMap(binding -> Option.of(binding.getSuperclass()))
                    .fold(() -> false, superclass -> equalsType(bind(superclass), qualifiedTypeNames));
        }

        static boolean equalsSuperType(final Either<ITypeBinding, Expression> expressionOrBinding,
                                       final String superTypeQualifiedName) {
            return findSuperType(expressionOrBinding, superTypeQualifiedName).fold(() -> false, binding -> true);
        }

        static List<Expression> expandTernary(final Expression expression) {
            return expression instanceof ConditionalExpression ? List.of(
                    ((ConditionalExpression) expression).getThenExpression(),
                    ((ConditionalExpression) expression).getElseExpression()) : List.of(expression);
        }

        static Stream<Expression> asExpression(final Collection<?> arguments) {
            return List.ofAll(arguments)
                    .filter(o -> Expression.class.isAssignableFrom(o.getClass()))
                    .map(Expression.class::cast)
                    .toStream();
        }

        static Option<ITypeBinding> getType(final Either<ITypeBinding, Expression> expressionOrBinding) {
            return expressionOrBinding.fold(Option::some, expression -> Option.of(expression.resolveTypeBinding()));
        }

        static Either<ITypeBinding, Expression> bind(final ITypeBinding iTypeBinding) {
            return Either.left(iTypeBinding);
        }

        static Either<ITypeBinding, Expression> bind(final Expression expression) {
            return Either.right(expression);
        }

        static <T> List<T> cons(final T head, final Iterable<? extends T> tail) {
            return Stream.concat(Option.of(head).toStream(), Stream.<T>ofAll(tail)).toList();
        }
    }

    private static void parseAST(String[] srcFiles,
                                 String[] classPathEntries, FileASTRequestor requestor) {

        Map<String, String> options = JavaCore.getOptions();
        setComplianceOptions(JavaCore.VERSION_1_8, options);

        ASTParser parser = ASTParser.newParser(AST.JLS11);
        parser.setCompilerOptions(options);
        parser.setKind(ASTParser.K_COMPILATION_UNIT);
        parser.setResolveBindings(true);
        parser.setBindingsRecovery(true);
        parser.setStatementsRecovery(true);
        parser.setEnvironment(classPathEntries, null, null, true);

        // assume UTF-8 for every source file
        String[] srcEncodings = Array.fill(srcFiles.length, UTF_8.name())
                .toJavaArray(String[]::new);
        parser.createASTs(srcFiles, srcEncodings, new String[]{}, requestor, null);
    }
}

class SourceAndCompilationUnit {

    final Path pathToSource;
    final String source;
    final CompilationUnit cu;

    SourceAndCompilationUnit(Path pathToSource, String source, CompilationUnit cu) {
        this.pathToSource = pathToSource;
        this.source = source;
        this.cu = cu;
    }
}