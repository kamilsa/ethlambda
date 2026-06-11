use std::collections::BTreeSet;

use ethlambda_types::{
    ShortRoot,
    attestation::{SignedAggregatedAttestation, SignedAttestation},
    block::SignedBlock,
    primitives::HashTreeRoot as _,
};
use libp2p::gossipsub::Event;
use libssz::{SszDecode, SszEncode};
use tracing::{error, info, trace};

use super::{
    encoding::{compress_message, decompress_message},
    messages::{
        AGGREGATION_TOPIC_KIND, ATTESTATION_SUBNET_TOPIC_PREFIX, BLOCK_TOPIC_KIND,
        attestation_subnet_topic,
    },
};
use crate::{P2PServer, metrics};

fn participant_subnets(
    attestation: &SignedAggregatedAttestation,
    attestation_committee_count: u64,
) -> Vec<u64> {
    attestation
        .proof
        .participant_indices()
        .map(|validator| validator % attestation_committee_count)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn message_kind_from_topic(topic: &str) -> &'static str {
    match topic.split("/").nth(3) {
        Some(BLOCK_TOPIC_KIND) => "block",
        Some(AGGREGATION_TOPIC_KIND) => "aggregation",
        Some(kind) if kind.starts_with(ATTESTATION_SUBNET_TOPIC_PREFIX) => "attestation",
        _ => "unknown",
    }
}

pub fn handle_raw_gossipsub_message(topic: &libp2p::gossipsub::TopicHash, bytes: usize) {
    metrics::record_p2p_bandwidth(
        "in",
        "gossip",
        message_kind_from_topic(topic.as_str()),
        bytes,
        "unfiltered",
    );
}

pub async fn handle_gossipsub_message(server: &mut P2PServer, event: Event) {
    let Event::Message {
        propagation_source,
        message_id,
        message,
    } = event
    else {
        unreachable!("we already matched on Message variant in handle_swarm_event");
    };
    let peer_count = server.connected_peers.len();
    match message_kind_from_topic(message.topic.as_str()) {
        "block" => {
            info!(kind = "block", peer_count, "P2P message received");
            let compressed_len = message.data.len();
            let Ok(uncompressed_data) = decompress_message(&message.data)
                .inspect_err(|err| error!(%err, "Failed to decompress gossipped block"))
            else {
                return;
            };
            metrics::observe_gossip_block_size(uncompressed_data.len(), compressed_len);

            let Ok(signed_block) = SignedBlock::from_ssz_bytes(&uncompressed_data)
                .inspect_err(|err| error!(?err, "Failed to decode gossipped block"))
            else {
                return;
            };
            let slot = signed_block.message.slot;
            let block_root = signed_block.message.hash_tree_root();
            let proposer = signed_block.message.proposer_index;
            let parent_root = signed_block.message.parent_root;
            let attestation_count = signed_block.message.body.attestations.len();
            info!(
                %slot,
                proposer,
                block_root = %ShortRoot(&block_root.0),
                parent_root = %ShortRoot(&parent_root.0),
                attestation_count,
                "Received block from gossip"
            );
            if let Some(ref blockchain) = server.blockchain {
                let _ = blockchain
                    .new_block(signed_block)
                    .inspect_err(|err| error!(%err, "Failed to forward block to blockchain"));
            }
        }
        "aggregation" => {
            info!(kind = "aggregation", peer_count, "P2P message received");
            let compressed_len = message.data.len();
            let Ok(uncompressed_data) = decompress_message(&message.data)
                .inspect_err(|err| error!(%err, "Failed to decompress gossipped aggregation"))
            else {
                return;
            };
            metrics::observe_gossip_aggregation_size(uncompressed_data.len(), compressed_len);

            let Ok(aggregation) = SignedAggregatedAttestation::from_ssz_bytes(&uncompressed_data)
                .inspect_err(|err| error!(?err, "Failed to decode gossipped aggregation"))
            else {
                return;
            };
            let slot = aggregation.data.slot;
            let data_root = aggregation.data.hash_tree_root();
            let participant_count = aggregation.proof.participants.count_ones();
            let participant_subnets =
                participant_subnets(&aggregation, server.attestation_committee_count);
            let local_peer_id = server.local_peer_id;
            let local_node = server.resolve_node_name(Some(&local_peer_id));
            let propagation_source_node = server.resolve_node_name(Some(&propagation_source));
            info!(
                event = "aggregation_received",
                %slot,
                %message_id,
                %local_peer_id,
                local_node,
                propagation_source = %propagation_source,
                propagation_source_node,
                message_source = ?message.source,
                data_root = %data_root,
                head_slot = aggregation.data.head.slot,
                head_root = %aggregation.data.head.root,
                target_slot = aggregation.data.target.slot,
                target_root = %aggregation.data.target.root,
                source_slot = aggregation.data.source.slot,
                source_root = %aggregation.data.source.root,
                participant_count,
                participant_subnets = ?participant_subnets,
                uncompressed_len = uncompressed_data.len(),
                compressed_len,
                "Received aggregated attestation from gossip"
            );
            if let Some(ref blockchain) = server.blockchain {
                let _ = blockchain
                    .new_aggregated_attestation(aggregation)
                    .inspect_err(
                        |err| error!(%err, "Failed to forward aggregated attestation to blockchain"),
                    );
            }
        }
        "attestation" => {
            info!(kind = "attestation", peer_count, "P2P message received");
            let compressed_len = message.data.len();
            let Ok(uncompressed_data) = decompress_message(&message.data)
                .inspect_err(|err| error!(%err, "Failed to decompress gossipped attestation"))
            else {
                return;
            };
            metrics::observe_gossip_attestation_size(uncompressed_data.len(), compressed_len);

            let Ok(signed_attestation) = SignedAttestation::from_ssz_bytes(&uncompressed_data)
                .inspect_err(|err| error!(?err, "Failed to decode gossipped attestation"))
            else {
                return;
            };
            let slot = signed_attestation.data.slot;
            let validator = signed_attestation.validator_id;
            info!(
                %slot,
                validator,
                head_root = %ShortRoot(&signed_attestation.data.head.root.0),
                target_slot = signed_attestation.data.target.slot,
                target_root = %ShortRoot(&signed_attestation.data.target.root.0),
                source_slot = signed_attestation.data.source.slot,
                source_root = %ShortRoot(&signed_attestation.data.source.root.0),
                "Received attestation from gossip"
            );
            if let Some(ref blockchain) = server.blockchain {
                let _ = blockchain
                    .new_attestation(signed_attestation)
                    .inspect_err(|err| error!(%err, "Failed to forward attestation to blockchain"));
            }
        }
        _ => {
            trace!("Received message on unknown topic: {}", message.topic);
        }
    }
}

pub async fn publish_attestation(server: &mut P2PServer, attestation: SignedAttestation) {
    let slot = attestation.data.slot;
    let validator = attestation.validator_id;
    let subnet_id = validator % server.attestation_committee_count;

    // Encode to SSZ
    let ssz_bytes = attestation.to_ssz();

    // Compress with raw snappy
    let compressed = compress_message(&ssz_bytes);

    metrics::observe_gossip_attestation_size(ssz_bytes.len(), compressed.len());
    metrics::record_p2p_bandwidth_for_slot(
        "out",
        "gossip",
        "attestation",
        compressed.len(),
        "sent",
        slot,
    );

    // Look up subscribed topic or construct on-the-fly for gossipsub fanout
    let topic = server
        .attestation_topics
        .get(&subnet_id)
        .cloned()
        .unwrap_or_else(|| attestation_subnet_topic(subnet_id));

    server.swarm_handle.publish(topic, compressed);
    info!(
        %slot,
        validator,
        subnet_id,
        target_slot = attestation.data.target.slot,
        target_root = %ShortRoot(&attestation.data.target.root.0),
        source_slot = attestation.data.source.slot,
        source_root = %ShortRoot(&attestation.data.source.root.0),
        "Published attestation to gossipsub"
    );
}

pub async fn publish_block(server: &mut P2PServer, signed_block: SignedBlock) {
    let slot = signed_block.message.slot;
    let proposer = signed_block.message.proposer_index;
    let block_root = signed_block.message.hash_tree_root();
    let parent_root = signed_block.message.parent_root;
    let attestation_count = signed_block.message.body.attestations.len();

    // Encode to SSZ
    let ssz_bytes = signed_block.to_ssz();

    // Compress with raw snappy
    let compressed = compress_message(&ssz_bytes);

    metrics::observe_gossip_block_size(ssz_bytes.len(), compressed.len());
    metrics::record_p2p_bandwidth_for_slot(
        "out",
        "gossip",
        "block",
        compressed.len(),
        "sent",
        slot,
    );

    // Publish to gossipsub
    server
        .swarm_handle
        .publish(server.block_topic.clone(), compressed);
    info!(
        %slot,
        proposer,
        block_root = %ShortRoot(&block_root.0),
        parent_root = %ShortRoot(&parent_root.0),
        attestation_count,
        "Published block to gossipsub"
    );
}

pub async fn publish_aggregated_attestation(
    server: &mut P2PServer,
    attestation: SignedAggregatedAttestation,
) {
    let slot = attestation.data.slot;

    // Encode to SSZ
    let ssz_bytes = attestation.to_ssz();

    // Compress with raw snappy
    let compressed = compress_message(&ssz_bytes);
    let compressed_len = compressed.len();
    let topic_hash = server.aggregation_topic.hash();
    let message_id = crate::compute_message_id_from_parts(&topic_hash, &compressed);
    let data_root = attestation.data.hash_tree_root();
    let participant_count = attestation.proof.participants.count_ones();
    let participant_subnets = participant_subnets(&attestation, server.attestation_committee_count);
    let local_peer_id = server.local_peer_id;
    let local_node = server.resolve_node_name(Some(&local_peer_id));

    metrics::observe_gossip_aggregation_size(ssz_bytes.len(), compressed_len);
    metrics::record_p2p_bandwidth_for_slot(
        "out",
        "gossip",
        "aggregation",
        compressed_len,
        "sent",
        slot,
    );

    // Publish to the aggregation topic
    server
        .swarm_handle
        .publish(server.aggregation_topic.clone(), compressed);
    info!(
        event = "aggregation_published",
        %slot,
        %message_id,
        %local_peer_id,
        local_node,
        topic = %topic_hash,
        data_root = %data_root,
        head_slot = attestation.data.head.slot,
        head_root = %attestation.data.head.root,
        target_slot = attestation.data.target.slot,
        target_root = %attestation.data.target.root,
        source_slot = attestation.data.source.slot,
        source_root = %attestation.data.source.root,
        participant_count,
        participant_subnets = ?participant_subnets,
        uncompressed_len = ssz_bytes.len(),
        compressed_len,
        "Published aggregated attestation to gossipsub"
    );
}
