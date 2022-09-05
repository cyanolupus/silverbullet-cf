import { syscall } from "./syscall";
import { AttachmentMeta, PageMeta } from "../common/types";

export async function listPages(unfiltered = false): Promise<PageMeta[]> {
  return syscall("space.listPages", unfiltered);
}

export async function getPageMeta(name: string): Promise<PageMeta> {
  return syscall("space.getPageMeta", name);
}

export async function readPage(
  name: string
): Promise<{ text: string; meta: PageMeta }> {
  return syscall("space.readPage", name);
}

export async function writePage(name: string, text: string): Promise<PageMeta> {
  return syscall("space.writePage", name, text);
}

export async function deletePage(name: string): Promise<void> {
  return syscall("space.deletePage", name);
}

export async function listAttachments(): Promise<PageMeta[]> {
  return syscall("space.listAttachments");
}

export async function getAttachmentMeta(name: string): Promise<AttachmentMeta> {
  return syscall("space.getAttachmentMeta", name);
}

export async function readAttachment(
  name: string
): Promise<{ data: string; meta: AttachmentMeta }> {
  return syscall("space.readAttachment", name);
}

export async function writeAttachment(
  name: string,
  buffer: ArrayBuffer
): Promise<AttachmentMeta> {
  return syscall("space.writeAttachment", name, buffer);
}

export async function deleteAttachment(name: string): Promise<void> {
  return syscall("space.deleteAttachment", name);
}
