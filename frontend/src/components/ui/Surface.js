import React from "react";

export default function Surface({ title, subtitle, children, className = "", bodyClassName = "" }) {
  return (
    <section className={`surface ${className}`.trim()}>
      {(title || subtitle) && (
        <div className="surface__head">
          <div>
            {title ? <h3 className="surface__title">{title}</h3> : null}
            {subtitle ? <div className="surface__subtitle">{subtitle}</div> : null}
          </div>
        </div>
      )}
      <div className={`surface__body ${bodyClassName}`.trim()}>{children}</div>
    </section>
  );
}
