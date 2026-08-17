import { ScanDetailClient } from "@/components/ScanDetailClient";

export default async function ScanPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <ScanDetailClient scanId={id} />;
}
