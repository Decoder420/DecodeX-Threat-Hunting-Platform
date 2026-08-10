import React, { useRef } from "react";
import gsap from "gsap";

const VARIANT_CLASS = {
  primary: "btn--primary",
  ghost: "btn--ghost",
  danger: "btn--danger",
  warn: "btn--warn",
  info: "btn--info",
};

export default function Button({
  children,
  variant = "ghost",
  size = "md",
  block = false,
  className = "",
  type = "button",
  onClick,
  disabled,
  ...rest
}) {
  const ref = useRef(null);

  const handleClick = (event) => {
    if (ref.current) {
      gsap.fromTo(
        ref.current,
        { scale: 0.97 },
        { scale: 1, duration: 0.22, ease: "power2.out" }
      );
    }
    if (onClick) onClick(event);
  };

  const classes = [
    "btn",
    VARIANT_CLASS[variant] || VARIANT_CLASS.ghost,
    size === "sm" ? "btn--sm" : "",
    block ? "btn--block" : "",
    className,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <button
      ref={ref}
      type={type}
      className={classes}
      onClick={handleClick}
      disabled={disabled}
      {...rest}
    >
      {children}
    </button>
  );
}
