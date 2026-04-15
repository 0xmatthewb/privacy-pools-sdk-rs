import React, { useEffect, useState } from "react";
import { ScrollView, Text, View } from "react-native";
import {
  ERROR_MARKER,
  SUCCESS_MARKER,
  markSmokeFailure,
  runReactNativeAppSmoke,
} from "./src/smoke";

type SmokeState =
  | { status: "running"; message: string }
  | { status: "success"; message: string }
  | { status: "error"; message: string };

export default function App() {
  const [state, setState] = useState<SmokeState>({
    status: "running",
    message: "running privacy pools react native smoke",
  });

  useEffect(() => {
    let cancelled = false;

    runReactNativeAppSmoke()
      .then(() => {
        if (!cancelled) {
          setState({ status: "success", message: SUCCESS_MARKER });
        }
      })
      .catch(async (error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        await markSmokeFailure(message);
        if (!cancelled) {
          setState({ status: "error", message: `${ERROR_MARKER}: ${message}` });
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <ScrollView>
      <View style={{ padding: 24 }}>
        <Text>{state.message}</Text>
      </View>
    </ScrollView>
  );
}
