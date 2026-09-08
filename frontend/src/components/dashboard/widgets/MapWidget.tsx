"use client";

import { Map as MaplibreMap, Marker, NavigationControl, Popup, type LngLatLike } from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import { useEffect, useRef } from "react";
import { Card } from "@/design-system/primitives/Card";
import { SectionHeader } from "@/design-system/primitives/SectionHeader";
import { EmptyState } from "@/design-system/primitives/States";
import { SEVERITY_HEX, type Severity } from "@/design-system/tokens";

export interface MapPoint {
  id: string;
  lng: number;
  lat: number;
  label: string;
  severity?: Severity;
}

export interface MapViewModel {
  id: string;
  title: string;
  points: MapPoint[];
  center?: LngLatLike;
  zoom?: number;
}

/**
 * Reusable MapLibre GL widget.
 *
 * Requires a configured vector tile style — `NEXT_PUBLIC_MAP_STYLE_URL`
 * (a MapLibre style JSON URL, e.g. a self-hosted tile server or a
 * provider's style endpoint). Per the platform-realization rule
 * ("do not fabricate live events" — extended here to "do not hardcode
 * a third-party tile URL"), this widget renders a configuration
 * prompt instead of silently pointing at an undeclared external
 * service when the env var is unset.
 */
export function MapWidget({ title, points, center, zoom = 1.5 }: MapViewModel) {
  const containerRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<MaplibreMap | null>(null);
  const styleUrl = process.env.NEXT_PUBLIC_MAP_STYLE_URL;

  useEffect(() => {
    if (!styleUrl || !containerRef.current || mapRef.current) return;

    const map = new MaplibreMap({
      container: containerRef.current,
      style: styleUrl,
      center: center ?? [0, 20],
      zoom,
    });
    map.addControl(new NavigationControl(), "top-right");
    mapRef.current = map;

    return () => {
      map.remove();
      mapRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [styleUrl]);

  useEffect(() => {
    const map = mapRef.current;
    if (!map) return;
    const markers: Marker[] = [];
    for (const point of points) {
      const color = point.severity ? SEVERITY_HEX[point.severity] : "#60a5fa";
      const marker = new Marker({ color })
        .setLngLat([point.lng, point.lat])
        .setPopup(new Popup({ offset: 12 }).setText(point.label))
        .addTo(map);
      markers.push(marker);
    }
    return () => {
      for (const marker of markers) marker.remove();
    };
  }, [points]);

  return (
    <Card>
      <SectionHeader title={title} />
      <div className="mt-3">
        {!styleUrl ? (
          <EmptyState
            message="Map tile source is not configured. Set NEXT_PUBLIC_MAP_STYLE_URL to a MapLibre style JSON URL to enable this map."
          />
        ) : (
          <div ref={containerRef} className="h-80 w-full overflow-hidden rounded-lg" />
        )}
      </div>
    </Card>
  );
}
