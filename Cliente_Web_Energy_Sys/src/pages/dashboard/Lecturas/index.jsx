"use client";
import React from "react";
import "@/styles/globals.css";
import DefaultLayout from "@/components/Layouts/DefaultLayout";
import Lecturas from "./Lecturas";
import { useState } from "react";

export default function Index_Lecturas() {
  return (
    <DefaultLayout>
      <Lecturas />
    </DefaultLayout>
  );
}
