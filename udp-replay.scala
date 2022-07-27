//> using scala "3.1.2"
//> using lib "co.fs2::fs2-io:3.2.11-1-19ce392-20220727T133109Z-SNAPSHOT"
//> using lib "co.fs2::fs2-protocols:3.2.11-1-19ce392-20220727T133109Z-SNAPSHOT"
//> using lib "com.monovore::decline::2.2.0"

import cats.data.NonEmptyList
import cats.effect.{ExitCode, IO, IOApp}
import cats.syntax.all.*
import com.comcast.ip4s.*
import com.monovore.decline.*
import fs2.{Chunk, Stream}
import fs2.io.file.{Files, Path}
import fs2.io.net.{Datagram, Network}
import fs2.protocols.pcap.CaptureFile
import fs2.timeseries.TimeStamped
import scala.concurrent.duration.*

object UdpReplay extends IOApp:
  def run(args: List[String]) =
    val command = Command(
      name = "udp-replay",
      header = "Replays UDP packets from a pcap file"
    ) {
      val file = Opts.argument[String](metavar = "file")
      val timescale = Opts.option[Double](
        "timescale",
        short = "t",
        metavar = "factor",
        help = "Speed at which replay occurs. 1.0 for replay at recorded rate, 2.0 for double speed, etc."
      ).withDefault(1.0)
      val destination = Opts.option[String](
        "destination",
        short = "d",
        metavar = "host",
        help = "Destination host to send replayed packets to."
      ).withDefault("127.0.0.1").mapValidated(h => Host.fromString(h).toValid(NonEmptyList.of(s"\"$h\" not a valid host")))
      val portMappings = Opts.options[String](
        "port",
        short = "p",
        metavar = "port-or-port-mapping",
        help = """When specified, datagrams that match the specified port(s) are replayed - if a mapping is specified, the destination port is modified before being replayed. For example, "-p 5555" replays any datagrams with destination port 5555 whereas "-p 5555:4444" changes the destination port to 4444. If not specified, then all datagrams in the input are replayed."""
      ).mapValidated { strings =>
        strings.traverse { s =>
          Port.fromString(s).map(p => (p, p)).orElse {
            s.split(":", 2) match
              case Array(from, to) =>
                (Port.fromString(from), Port.fromString(to)).tupled
          }.toValid(NonEmptyList.of(s"\"$s\" not a port or a port mapping"))
        }
      }.orNone.map { portMappings =>
        portMappings.map(_.toList.toMap.get).getOrElse((p: Port) => Some(p))
      }
      (file, timescale, destination, portMappings).tupled
    }
    command.parse(args) match
      case Left(help) => IO(System.err.println(help)).as(ExitCode(-1))
      case Right((file, timescale, destination, portMapping)) =>
        replay(Path(file), timescale, destination, portMapping).compile.drain.as(ExitCode.Success)

  def replay(file: Path, timescale: Double, destination: Host, portMap: Port => Option[Port]): Stream[IO, Nothing] =
    Files[IO]
      .readAll(file)
      .through(CaptureFile.udpDatagrams.toPipeByte)
      .through(TimeStamped.throttle(timescale, 1.second))
      .map(_.value)
      .through(changeDestination(destination, portMap))
      .through(sendAll)

  def changeDestination(destination: Host, portMap: Port => Option[Port])(datagrams: Stream[IO, CaptureFile.DatagramRecord]): Stream[IO, Datagram] =
    Stream.eval(destination.resolve[IO]).flatMap { destinationIp =>
      datagrams.flatMap(packet =>
        portMap(packet.udp.destinationPort) match
          case Some(destPort) =>
            Stream(Datagram(SocketAddress(destinationIp, destPort), packet.payload))
          case None => Stream.empty
      )
    }

  def sendAll(datagrams: Stream[IO, Datagram]): Stream[IO, Nothing] =
    Stream.resource(Network[IO].openDatagramSocket()).flatMap { socket =>
      datagrams.through(socket.writes)
    }
