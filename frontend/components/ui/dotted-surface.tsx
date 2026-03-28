"use client";

import { useTheme } from "next-themes";
import React, { useEffect, useRef } from "react";
import * as THREE from "three";
import { cn } from "@/lib/utils";

type DottedSurfaceProps = Omit<React.ComponentProps<"div">, "ref">;

export function DottedSurface({ className, ...props }: DottedSurfaceProps) {
  const { resolvedTheme } = useTheme();

  const containerRef = useRef<HTMLDivElement>(null);
  const sceneRef = useRef<{
    scene: THREE.Scene;
    camera: THREE.PerspectiveCamera;
    renderer: THREE.WebGLRenderer;
    particles: THREE.Points[];
    animationId: number;
    count: number;
  } | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const container = containerRef.current;
    const SEPARATION = 130;
    const AMOUNTX = 46;
    const AMOUNTY = 72;
    const darkMode = resolvedTheme !== "light";

    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(darkMode ? 0x050505 : 0xffffff, 1800, 10000);

    const camera = new THREE.PerspectiveCamera(
      58,
      window.innerWidth / window.innerHeight,
      1,
      10000
    );
    camera.position.set(0, 315, 1180);

    const renderer = new THREE.WebGLRenderer({
      alpha: true,
      antialias: true,
    });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.75));
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(scene.fog.color, 0);

    container.appendChild(renderer.domElement);

    const particles: THREE.Points[] = [];
    const positions: number[] = [];
    const colors: number[] = [];
    const geometry = new THREE.BufferGeometry();

    for (let ix = 0; ix < AMOUNTX; ix += 1) {
      for (let iy = 0; iy < AMOUNTY; iy += 1) {
        const x = ix * SEPARATION - (AMOUNTX * SEPARATION) / 2;
        const y = 0;
        const z = iy * SEPARATION - (AMOUNTY * SEPARATION) / 2;

        positions.push(x, y, z);

        if (darkMode) {
          colors.push(215, 215, 215);
        } else {
          colors.push(24, 24, 27);
        }
      }
    }

    geometry.setAttribute(
      "position",
      new THREE.Float32BufferAttribute(positions, 3)
    );
    geometry.setAttribute("color", new THREE.Float32BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
      size: 6.5,
      vertexColors: true,
      transparent: true,
      opacity: 0.88,
      sizeAttenuation: true,
    });

    const points = new THREE.Points(geometry, material);
    scene.add(points);
    particles.push(points);

    let count = 0;
    let animationId = 0;

    const animate = () => {
      animationId = requestAnimationFrame(animate);

      const positionAttribute = geometry.attributes.position;
      const values = positionAttribute.array as Float32Array;

      let i = 0;
      for (let ix = 0; ix < AMOUNTX; ix += 1) {
        for (let iy = 0; iy < AMOUNTY; iy += 1) {
          const index = i * 3;
          values[index + 1] =
            Math.sin((ix + count) * 0.28) * 44 +
            Math.sin((iy + count) * 0.44) * 44;
          i += 1;
        }
      }

      positionAttribute.needsUpdate = true;
      renderer.render(scene, camera);
      count += 0.08;
    };

    const handleResize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    };

    window.addEventListener("resize", handleResize);
    animate();

    sceneRef.current = {
      scene,
      camera,
      renderer,
      particles,
      animationId,
      count,
    };

    return () => {
      window.removeEventListener("resize", handleResize);

      if (sceneRef.current) {
        cancelAnimationFrame(sceneRef.current.animationId);

        sceneRef.current.scene.traverse((object) => {
          if (object instanceof THREE.Points) {
            object.geometry.dispose();
            if (Array.isArray(object.material)) {
              object.material.forEach((entry) => entry.dispose());
            } else {
              object.material.dispose();
            }
          }
        });

        sceneRef.current.renderer.dispose();

        if (container.contains(sceneRef.current.renderer.domElement)) {
          container.removeChild(sceneRef.current.renderer.domElement);
        }
      }
    };
  }, [resolvedTheme]);

  return (
    <div
      ref={containerRef}
      className={cn("pointer-events-none fixed inset-0 z-0", className)}
      {...props}
    />
  );
}
