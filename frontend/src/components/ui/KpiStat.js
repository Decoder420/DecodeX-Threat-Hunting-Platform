import React, { useEffect, useRef } from "react";
import gsap from "gsap";

export default function KpiStat({ title, value, hint, icon = "◆" }) {
  const valueRef = useRef(null);
  const cardRef = useRef(null);

  useEffect(() => {
    const el = valueRef.current;
    const card = cardRef.current;
    if (!el || !card) return undefined;

    gsap.fromTo(
      card,
      { y: 18, opacity: 0 },
      { y: 0, opacity: 1, duration: 0.55, ease: "power3.out" }
    );

    const numeric = Number(value);
    if (!Number.isFinite(numeric)) {
      el.textContent = String(value ?? "—");
      return undefined;
    }

    const state = { n: 0 };
    const tween = gsap.to(state, {
      n: numeric,
      duration: 0.9,
      ease: "power2.out",
      onUpdate: () => {
        el.textContent = Math.round(state.n).toLocaleString();
      },
    });

    return () => tween.kill();
  }, [value]);

  return (
    <article ref={cardRef} className="surface kpi">
      <div style={{ display: "flex", justifyContent: "space-between" }}>
        <div className="kpi__label">{title}</div>
        <div className="kpi__icon" aria-hidden>
          {icon}
        </div>
      </div>
      <div>
        <div ref={valueRef} className="kpi__value">
          {typeof value === "number" ? "0" : value}
        </div>
        {hint ? <div className="kpi__meta">{hint}</div> : null}
      </div>
    </article>
  );
}
