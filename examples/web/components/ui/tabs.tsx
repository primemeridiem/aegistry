"use client";

import * as TabsPrimitive from "@radix-ui/react-tabs";
import type * as React from "react";
import { cn } from "../../lib/utils";

function Tabs({
	className,
	...props
}: React.ComponentProps<typeof TabsPrimitive.Root>) {
	return (
		<TabsPrimitive.Root
			data-slot="tabs"
			className={cn("flex flex-col", className)}
			{...props}
		/>
	);
}

function TabsList({
	className,
	...props
}: React.ComponentProps<typeof TabsPrimitive.List>) {
	return (
		<TabsPrimitive.List
			data-slot="tabs-list"
			className={cn("inline-flex w-fit items-center", className)}
			{...props}
		/>
	);
}

function TabsTrigger({
	className,
	...props
}: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
	return (
		<TabsPrimitive.Trigger
			data-slot="tabs-trigger"
			className={cn(
				"inline-flex items-center justify-center whitespace-nowrap border px-5 py-2.5 text-sm transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 data-[state=inactive]:-ml-px data-[state=inactive]:first:ml-0 data-[state=inactive]:border-border data-[state=inactive]:border-b-transparent data-[state=inactive]:bg-secondary/40 data-[state=inactive]:text-muted-foreground data-[state=inactive]:hover:text-foreground data-[state=active]:border-border data-[state=active]:border-b-card data-[state=active]:bg-card data-[state=active]:text-foreground",
				className,
			)}
			{...props}
		/>
	);
}

function TabsContent({
	className,
	...props
}: React.ComponentProps<typeof TabsPrimitive.Content>) {
	return (
		<TabsPrimitive.Content
			data-slot="tabs-content"
			className={cn("outline-none", className)}
			{...props}
		/>
	);
}

export { Tabs, TabsList, TabsTrigger, TabsContent };
