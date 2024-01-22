// Copyright 2023 The Trusted Computations Platform Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate prost;
extern crate tcp_atomic_counter_service;
extern crate tcp_integration;
extern crate tcp_proto;

#[cfg(all(test, feature = "std"))]
mod test {

    use prost::Message;
    use std::collections::BTreeMap;
    use tcp_atomic_counter_service::actor::CounterActor;
    use tcp_atomic_counter_service::apps::atomic_counter::service::*;
    use tcp_integration::harness::*;
    use tcp_proto::runtime::endpoint::*;

    fn send_cas_counter_request(
        cluster: &mut FakeCluster<CounterActor>,
        node_id: u64,
        request_id: u64,
        counter_name: &str,
        expected_value: i64,
        new_value: i64,
    ) {
        let counter_request = CounterRequest {
            id: request_id,
            name: counter_name.to_string(),
            op: Some(counter_request::Op::CompareAndSwap(
                CounterCompareAndSwapRequest {
                    expected_value,
                    new_value,
                },
            )),
            ..Default::default()
        };

        cluster.send_proposal(node_id, counter_request.encode_to_vec().into())
    }

    fn advance_until_counter_response(
        cluster: &mut FakeCluster<CounterActor>,
        response_id: u64,
    ) -> CounterResponse {
        let mut counter_response_opt: Option<CounterResponse> = None;
        let response_messages =
            cluster.advance_until(&mut |envelope_out| match &envelope_out.msg {
                Some(out_message::Msg::ExecuteProposal(response)) => {
                    let counter_response =
                        CounterResponse::decode(response.result_contents.as_ref()).unwrap();
                    if counter_response.id == response_id {
                        counter_response_opt = Some(counter_response);
                        return true;
                    }
                    false
                }
                _ => false,
            });

        assert!(!response_messages.is_empty());

        counter_response_opt.unwrap()
    }

    fn advance_until_cas_counter_response(
        cluster: &mut FakeCluster<CounterActor>,
        counter_request_id: u64,
        counter_response_status: CounterStatus,
        old_value: i64,
        new_value: i64,
    ) -> bool {
        let counter_response = advance_until_counter_response(cluster, counter_request_id);

        let counter_op = if counter_response_status == CounterStatus::Success {
            Some(counter_response::Op::CompareAndSwap(
                CounterCompareAndSwapResponse {
                    old_value,
                    new_value,
                },
            ))
        } else {
            None
        };

        counter_response
            == CounterResponse {
                id: counter_request_id,
                status: counter_response_status.into(),
                op: counter_op,
            }
    }

    #[test]
    fn integration() {
        let counter_name_1 = "counter 1";
        let counter_value_1: i64 = 10;
        let counter_name_2 = "counter 2";
        let counter_value_2: i64 = 15;
        let config = CounterConfig {
            initial_values: BTreeMap::from([
                (counter_name_1.to_string(), counter_value_1),
                (counter_name_2.to_string(), counter_value_2),
            ]),
        };

        let mut cluster = FakeCluster::new(config.encode_to_vec().into());

        cluster.start_node(1, true, CounterActor::new());
        cluster.advance_until_elected_leader(None);
        assert!(cluster.leader_id() == 1);

        cluster.start_node(2, false, CounterActor::new());
        cluster.start_node(3, false, CounterActor::new());

        cluster.add_node_to_cluster(2);

        let mut leader_id = cluster.leader_id();
        send_cas_counter_request(
            &mut cluster,
            leader_id,
            1,
            counter_name_1,
            counter_value_1,
            counter_value_1 + 1,
        );
        send_cas_counter_request(
            &mut cluster,
            leader_id,
            2,
            counter_name_2,
            counter_value_2,
            counter_value_2 + 1,
        );

        assert!(advance_until_cas_counter_response(
            &mut cluster,
            1,
            CounterStatus::Success,
            counter_value_1,
            counter_value_1 + 1
        ));
        assert!(advance_until_cas_counter_response(
            &mut cluster,
            2,
            CounterStatus::Success,
            counter_value_2,
            counter_value_2 + 1
        ));

        cluster.add_node_to_cluster(3);

        let non_leader_id = cluster.non_leader_id();
        send_cas_counter_request(
            &mut cluster,
            non_leader_id,
            3,
            counter_name_1,
            counter_value_1 + 1,
            counter_value_1 + 2,
        );
        assert!(advance_until_cas_counter_response(
            &mut cluster,
            3,
            CounterStatus::Rejected,
            0,
            0
        ));

        leader_id = cluster.leader_id();
        cluster.stop_node(leader_id);
        cluster.advance_until_elected_leader(Some(leader_id));

        leader_id = cluster.leader_id();
        send_cas_counter_request(
            &mut cluster,
            leader_id,
            4,
            counter_name_2,
            counter_value_2 + 1,
            counter_value_2 + 2,
        );
        assert!(advance_until_cas_counter_response(
            &mut cluster,
            4,
            CounterStatus::Success,
            counter_value_2 + 1,
            counter_value_2 + 2
        ));
    }
}
