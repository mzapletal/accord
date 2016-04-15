package org.neociclo.accord.components.oftpcmd;

import org.apache.commons.cli.Option;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface CommandLineOption {

	boolean required() default false;

	boolean hasArg() default true;

	String description() default "";

	String name() default "";

	Class<? extends CommandOptionConverter<?>> converter() default CommandOptionConverter.NullConverter.class;

	int hasArgs() default Option.UNINITIALIZED;

}
